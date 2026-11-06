import test from "node:test";
import assert from "node:assert/strict";
import {
  redactSensitive,
  classifyShellCommand,
  auditConfigObject,
  parseSessionCommands,
  scoreFindings,
  generateLeastPrivilegePolicy,
} from "../src/analyzer.mjs";

test("redactSensitive masks public IPv4 addresses, API keys, and base64 hooks while preserving 127.0.0.1", () => {
  const input =
    "ssh root@31.97.202.108 'curl http://127.0.0.1:8080 -H \"Authorization: Bearer sk-1d52406427d6fe00015a454b07acfa\"'";
  const out = redactSensitive(input, true);
  assert.ok(!out.includes("31.97.202.108"), "should mask public IPv4");
  assert.ok(out.includes("<REDACTED_IP>"), "should insert <REDACTED_IP>");
  assert.ok(out.includes("127.0.0.1"), "should preserve localhost IP");
  assert.ok(!out.includes("1d52406427d6fe00015a454b07acfa"), "should mask secret token");
});

test("classifyShellCommand separates ephemeral /tmp rm -rf (ABL014) from workspace rm -rf (ABL008)", () => {
  const tmpCmd1 = "cd /tmp && rm -rf obskill && mkdir obskill";
  const f1 = classifyShellCommand(tmpCmd1, "s1.jsonl");
  assert.ok(f1.some((f) => f.ruleId === "ABL014"), "cd /tmp && rm -rf relative should be ABL014");
  assert.ok(!f1.some((f) => f.ruleId === "ABL008"), "cd /tmp && rm -rf relative must not trigger ABL008");

  const tmpCmd2 = "rm -rf /tmp/quantiti-head";
  const f2 = classifyShellCommand(tmpCmd2, "s2.jsonl");
  assert.ok(f2.some((f) => f.ruleId === "ABL014"));
  assert.ok(!f2.some((f) => f.ruleId === "ABL008"));

  const dangerousCmd = "rm -rf ./dist /var/lib/postgresql/data";
  const f3 = classifyShellCommand(dangerousCmd, "s3.jsonl");
  assert.ok(f3.some((f) => f.ruleId === "ABL008"), "non-/tmp rm -rf must trigger ABL008 CRITICAL");
});

test("classifyShellCommand detects root SSH and distinguishes read-only probe vs remote mutation", () => {
  const roSsh = "ssh root@203.0.113.9 'ls -la /opt/app && journalctl -n 20'";
  const fRo = classifyShellCommand(roSsh, "ro.jsonl");
  const hitRo = fRo.find((f) => f.ruleId === "ABL007");
  assert.ok(hitRo);
  assert.equal(hitRo.meta.isRoot, true);
  assert.equal(hitRo.meta.isMutatingRemote, false);

  const mutSsh = "ssh root@203.0.113.9 'systemctl restart app.service'";
  const fMut = classifyShellCommand(mutSsh, "mut.jsonl");
  const hitMut = fMut.find((f) => f.ruleId === "ABL007");
  assert.ok(hitMut);
  assert.equal(hitMut.meta.isMutatingRemote, true);
});

test("parseSessionCommands deduplicates streaming tool_use.id and Codex call_id rows", () => {
  const jsonl = [
    JSON.stringify({
      type: "assistant",
      message: {
        id: "msg_1",
        content: [{ type: "tool_use", id: "toolu_abc", name: "Bash", input: { command: "git status" } }],
      },
    }),
    JSON.stringify({
      type: "assistant",
      message: {
        id: "msg_1",
        content: [{ type: "tool_use", id: "toolu_abc", name: "Bash", input: { command: "git status" } }],
      },
    }),
    JSON.stringify({
      type: "response_item",
      payload: {
        type: "function_call",
        name: "exec_command",
        call_id: "call_99",
        arguments: JSON.stringify({ cmd: "npm test" }),
      },
    }),
  ].join("\n");

  const parsed = parseSessionCommands(jsonl, "test.jsonl");
  assert.equal(parsed.rawToolRows, 3);
  assert.equal(parsed.deduplicatedToolCalls, 2);
});

test("auditConfigObject flags plaintext API keys, missing deny rules, and file credential stores", () => {
  const findings = auditConfigObject({
    claudeSettings: {
      env: { ANTHROPIC_API_KEY: "sk-ant-1234567890abcdef12345678" },
      dangerouslySkipPermissions: true,
    },
    codexConfigText: 'cli_auth_credentials_store = "file"\n',
  });
  const ids = new Set(findings.map((f) => f.ruleId));
  assert.ok(ids.has("ABL001"));
  assert.ok(ids.has("ABL002"));
  assert.ok(ids.has("ABL003"));
  assert.ok(ids.has("ABL005"));

  const scored = scoreFindings(findings);
  assert.ok(scored.safetyScore < 50);

  const policy = generateLeastPrivilegePolicy();
  assert.ok(Array.isArray(policy.permissions.deny));
  assert.ok(policy.permissions.deny.includes("Bash(ssh root@*)"));
});
