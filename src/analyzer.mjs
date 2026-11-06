import fs from "node:fs";
import path from "node:path";
import os from "node:os";

export const RULES = [
  {
    id: "ABL001",
    plane: "config",
    severity: "CRITICAL",
    weight: 22,
    cap: 22,
    title: "Plaintext API key or auth token in agent config env",
    fix: "Remove literal API keys from ~/.claude/settings.json env block and load via OS keychain or shell environment.",
  },
  {
    id: "ABL002",
    plane: "config",
    severity: "CRITICAL",
    weight: 20,
    cap: 20,
    title: "Unrestricted wildcard shell or bypass-permissions mode enabled",
    fix: "Replace Bash(*) or dangerouslySkipPermissions with scoped command allowlists (e.g. Bash(npm test:*), Bash(git status:*)).",
  },
  {
    id: "ABL003",
    plane: "config",
    severity: "HIGH",
    weight: 14,
    cap: 14,
    title: "Missing permissions.deny guardrail blocklist in Claude Code settings",
    fix: "Add permissions.deny blocking Bash(ssh root@*), Bash(rm -rf /*), Bash(git push --force*), Read(**/.env*), and Read(~/.ssh/*).",
  },
  {
    id: "ABL004",
    plane: "config",
    severity: "HIGH",
    weight: 12,
    cap: 12,
    title: "Encoded or obfuscated shell command in lifecycle hook",
    fix: "Audit SessionStart/PreToolUse hooks and replace -EncodedCommand / base64 payloads with readable, versioned scripts.",
  },
  {
    id: "ABL005",
    plane: "config",
    severity: "MEDIUM",
    weight: 10,
    cap: 10,
    title: "Plaintext file credential store in Codex CLI config",
    fix: "Set cli_auth_credentials_store = \"keychain\" in ~/.codex/config.toml instead of \"file\".",
  },
  {
    id: "ABL006",
    plane: "config",
    severity: "MEDIUM",
    weight: 6,
    cap: 12,
    title: "Broad auto-trusted project roots across external or production volumes",
    fix: "Prune stale [projects.\"...\"].trust_level = \"trusted\" entries in ~/.codex/config.toml.",
  },
  {
    id: "ABL007",
    plane: "transcript",
    severity: "CRITICAL",
    weight: 25,
    cap: 30,
    title: "Unrestricted root/remote SSH execution from agent shell",
    fix: "Deny Bash(ssh root@*) in permissions.deny; use a read-only ops-reader SSH user with ForceCommand for log inspection.",
  },
  {
    id: "ABL008",
    plane: "transcript",
    severity: "CRITICAL",
    weight: 24,
    cap: 24,
    title: "Destructive recursive deletion (rm -rf) outside ephemeral /tmp",
    fix: "Block non-/tmp rm -rf via permissions.deny or a PreToolUse guard hook.",
  },
  {
    id: "ABL009",
    plane: "transcript",
    severity: "CRITICAL",
    weight: 22,
    cap: 22,
    title: "Destructive cloud, container, or database mutation command",
    fix: "Block terraform destroy, kubectl delete, DROP TABLE, TRUNCATE, and aws rds delete-db-instance in permissions.deny.",
  },
  {
    id: "ABL010",
    plane: "transcript",
    severity: "HIGH",
    weight: 14,
    cap: 20,
    title: "Shell command reading .env, credential files, or live service secrets",
    fix: "Add Read(**/.env*), Read(~/.npmrc), Read(~/.ssh/*), and Bash(* .env*) to permissions.deny.",
  },
  {
    id: "ABL011",
    plane: "transcript",
    severity: "HIGH",
    weight: 15,
    cap: 15,
    title: "Destructive git history rewrite or hook bypass (--force, reset --hard, --no-verify)",
    fix: "Add Bash(git push --force*), Bash(git reset --hard*), and Bash(* --no-verify*) to permissions.deny.",
  },
  {
    id: "ABL012",
    plane: "transcript",
    severity: "HIGH",
    weight: 12,
    cap: 18,
    title: "Production service or daemon control (systemctl, pm2, nginx, docker)",
    fix: "Restrict daemon control to read-only status subcommands (e.g. systemctl is-active, systemctl status).",
  },
  {
    id: "ABL013",
    plane: "transcript",
    severity: "MEDIUM",
    weight: 10,
    cap: 14,
    title: "Agent reading or mutating its own harness config (~/.claude, ~/.codex, .git/hooks)",
    fix: "Deny write access to ~/.claude/, ~/.codex/, and .git/hooks/ so an agent cannot weaken its own harness.",
  },
  {
    id: "ABL014",
    plane: "transcript",
    severity: "LOW",
    weight: 3,
    cap: 9,
    title: "Ephemeral /tmp recursive cleanup or unpinned remote package execution",
    fix: "Pin npx package versions and prefer mkdtemp scoped directories for scratch operations.",
  },
];

export const RULE_MAP = Object.fromEntries(RULES.map((r) => [r.id, r]));

export function redactSensitive(text, redact = true) {
  if (!text || !redact) return String(text || "");
  return String(text)
    .replace(/\b(?:sk-ant-[a-zA-Z0-9_-]{8,}|sk-[a-zA-Z0-9_-]{16,}|ghp_[a-zA-Z0-9]{16,}|gho_[a-zA-Z0-9]{16,}|npm_[a-zA-Z0-9]{16,}|AKIA[0-9A-Z]{12,})\b/g, (m) => m.slice(0, 5) + "<REDACTED>")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (ip) => (ip === "127.0.0.1" || ip === "0.0.0.0" ? ip : "<REDACTED_IP>"))
    .replace(/(-EncodedCommand\s+)[A-Za-z0-9+/=]{24,}/g, "$1<REDACTED_B64>");
}

function isEphemeralTmpRm(cmd) {
  // Find all rm -rf / rm -fr invocations and inspect target argument(s)
  const rmMatches = [...cmd.matchAll(/\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+([^\n;&|]+)/g)];
  if (rmMatches.length === 0) return null;
  let hasNonTmp = false;
  // Also check if cwd was switched to /tmp right before rm -rf <relative>
  const cdTmpBefore = /\bcd\s+(\/tmp|"\$TMPDIR"|\$TMPDIR)\b/.test(cmd);
  for (const m of rmMatches) {
    const rawTargets = m[2]
      .trim()
      .split(/\s+/)
      .filter((t) => t && !t.startsWith("-"));
    for (const raw of rawTargets) {
      const clean = raw.replace(/^['"]|['"]$/g, "");
      const isTmpPath =
        clean.startsWith("/tmp/") ||
        clean.startsWith("/private/tmp/") ||
        clean.startsWith("$TMPDIR/") ||
        clean.startsWith("${TMPDIR}") ||
        (cdTmpBefore && !clean.startsWith("/") && !clean.startsWith("~") && !clean.startsWith(".."));
      if (!isTmpPath) {
        hasNonTmp = true;
      }
    }
  }
  return hasNonTmp ? "NON_TMP" : "TMP_ONLY";
}

export function classifyShellCommand(cmd, sourceFile = "session.jsonl", redact = true) {
  const findings = [];
  const snippet = redactSensitive(cmd.replace(/\s+/g, " ").trim().slice(0, 140), redact);

  // ABL007: SSH / SCP / RSYNC to remote or root host
  if (/(?:^|[;&|]\s*|\b)(ssh|scp|rsync)\b/i.test(cmd) && (/@/.test(cmd) || /\broot\b/.test(cmd))) {
    const isRoot = /\broot@/.test(cmd);
    const isMutatingRemote = /\b(systemctl\s+(restart|stop|start|enable|disable|daemon-reload)|rm\s+|mv\s+|cp\s+|docker\s+(restart|stop|rm|run|exec)|pm2\s+(restart|reload|stop|delete)|kill\b|curl\b.*-X\s*(POST|PUT|DELETE))/i.test(cmd);
    findings.push({
      ruleId: "ABL007",
      source: sourceFile,
      detail: `${isRoot ? "root SSH" : "remote SSH"} (${isMutatingRemote ? "remote state mutation" : "read-only probe over unrestricted shell"}): ${snippet}`,
      meta: { isRoot, isMutatingRemote },
    });
  }

  // ABL008 vs ABL014: rm -rf classification
  if (/\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b/.test(cmd)) {
    const kind = isEphemeralTmpRm(cmd);
    if (kind === "NON_TMP") {
      findings.push({
        ruleId: "ABL008",
        source: sourceFile,
        detail: `Non-ephemeral rm -rf execution: ${snippet}`,
      });
    } else if (kind === "TMP_ONLY") {
      findings.push({
        ruleId: "ABL014",
        source: sourceFile,
        detail: `Ephemeral /tmp recursive cleanup: ${snippet}`,
      });
    }
  }

  // ABL009: Destructive cloud / DB / k8s / terraform mutations
  if (/\b(terraform\s+(destroy|apply\s+-auto-approve)|kubectl\s+delete\b|aws\s+rds\s+delete|DROP\s+(TABLE|DATABASE)|TRUNCATE\s+TABLE|redis-cli\s+.*FLUSH(ALL|DB))\b/i.test(cmd)) {
    findings.push({
      ruleId: "ABL009",
      source: sourceFile,
      detail: `Destructive infra/DB mutation: ${snippet}`,
    });
  }

  // ABL010: Secret / credential file access in shell
  if (/(?:^|\s|['"\/])(\.env(?:\.[a-zA-Z0-9_-]+)?|\.npmrc|id_rsa|id_ed25519|\.aws\/credentials|auth\.json)\b|\b(gh\s+auth\s+token|printenv)\b/.test(cmd)) {
    findings.push({
      ruleId: "ABL010",
      source: sourceFile,
      detail: `Credential or .env access in shell: ${snippet}`,
    });
  }

  // ABL011: Destructive git history or hook bypass
  if (/\bgit\s+(push\s+[^\n;&|]*(-f\b|--force\b)(?!-with-lease)|reset\s+--hard\b|clean\s+-[a-zA-Z]*f)|\b--no-verify\b/.test(cmd)) {
    findings.push({
      ruleId: "ABL011",
      source: sourceFile,
      detail: `Destructive git history or hook bypass: ${snippet}`,
    });
  }

  // ABL012: Production service / daemon control
  if (/\b(systemctl\s+(status|is-active|restart|stop|start|reload)|pm2\s+(restart|stop|delete|reload)|nginx\s+-s|docker\s+(ps|exec|run|rm|stop|kill|system\s+prune))\b/.test(cmd)) {
    findings.push({
      ruleId: "ABL012",
      source: sourceFile,
      detail: `Service or container daemon command: ${snippet}`,
    });
  }

  // ABL013: Self-harness access (~/.claude, ~/.codex, .git/hooks)
  if (/(\/\.claude\/|\/\.codex\/|\.git\/hooks\/|--dangerously-skip-permissions)/.test(cmd)) {
    findings.push({
      ruleId: "ABL013",
      source: sourceFile,
      detail: `Agent harness/config path accessed from shell: ${snippet}`,
    });
  }

  // ABL014: Unpinned curl | sh
  if (/\bcurl\b[^\n|]*\|\s*(sh|bash|zsh)\b/.test(cmd)) {
    findings.push({
      ruleId: "ABL014",
      source: sourceFile,
      detail: `Unpinned curl pipe to shell: ${snippet}`,
    });
  }

  return findings;
}

export function auditConfigObject({ claudeSettings, claudeSettingsPath = "~/.claude/settings.json", codexConfigText, codexConfigPath = "~/.codex/config.toml", redact = true }) {
  const findings = [];

  if (claudeSettings && typeof claudeSettings === "object") {
    const env = claudeSettings.env || {};
    for (const [k, v] of Object.entries(env)) {
      if (typeof v === "string" && (/KEY|TOKEN|SECRET|PASSWORD/i.test(k) || /^sk-[a-zA-Z0-9_-]{12,}/.test(v)) && !v.startsWith("$")) {
        findings.push({
          ruleId: "ABL001",
          source: claudeSettingsPath,
          detail: `Plaintext secret in env.${k} = "${redactSensitive(v, redact)}"`,
        });
      }
    }

    const perms = claudeSettings.permissions || {};
    const allow = Array.isArray(perms.allow) ? perms.allow : [];
    const deny = Array.isArray(perms.deny) ? perms.deny : [];

    if (claudeSettings.dangerouslySkipPermissions === true || allow.some((a) => /^Bash\(\*\)$|^Bash$/i.test(String(a).trim()))) {
      findings.push({
        ruleId: "ABL002",
        source: claudeSettingsPath,
        detail: `Unrestricted shell permission enabled (${claudeSettings.dangerouslySkipPermissions ? "dangerouslySkipPermissions: true" : "Bash(*)"})`,
      });
    }

    if (deny.length === 0) {
      findings.push({
        ruleId: "ABL003",
        source: claudeSettingsPath,
        detail: `No permissions.deny blocklist configured (0 deny rules guarding root SSH, rm -rf, .env, or ~/.ssh)`,
      });
    }

    const hooksText = JSON.stringify(claudeSettings.hooks || {});
    if (/-EncodedCommand\b|base64\s+(-d|--decode)\s*\|\s*(sh|bash)|\beval\s+/i.test(hooksText)) {
      findings.push({
        ruleId: "ABL004",
        source: claudeSettingsPath,
        detail: `Encoded command payload detected in lifecycle hooks (${redactSensitive(hooksText.slice(0, 120), redact)}...)`,
      });
    }
  }

  if (typeof codexConfigText === "string" && codexConfigText.trim()) {
    if (/cli_auth_credentials_store\s*=\s*"file"/.test(codexConfigText)) {
      findings.push({
        ruleId: "ABL005",
        source: codexConfigPath,
        detail: `cli_auth_credentials_store = "file" stores auth credentials in plaintext disk file instead of OS keychain`,
      });
    }
    if (/approval_policy\s*=\s*"never"|sandbox_mode\s*=\s*"danger-full-access"/.test(codexConfigText)) {
      findings.push({
        ruleId: "ABL002",
        source: codexConfigPath,
        detail: `Codex config disables approval/sandbox gate (approval_policy = "never" or danger-full-access)`,
      });
    }
    const trustedMatches = [...codexConfigText.matchAll(/\[projects\."([^"]+)"\][\s\S]*?trust_level\s*=\s*"trusted"/g)];
    if (trustedMatches.length >= 5) {
      findings.push({
        ruleId: "ABL006",
        source: codexConfigPath,
        detail: `${trustedMatches.length} auto-trusted project roots configured in ~/.codex/config.toml (including external volumes)`,
      });
    }
  }

  return findings;
}

function walkJsonl(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walkJsonl(full, out);
    else if (e.isFile() && e.name.endsWith(".jsonl")) out.push(full);
  }
  return out;
}

export function parseSessionCommands(jsonlText, sourceLabel = "session.jsonl") {
  const lines = jsonlText.split("\n");
  const seenToolIds = new Set();
  let rawToolRows = 0;
  const commands = [];

  for (const line of lines) {
    if (!line.trim()) continue;
    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      continue;
    }

    if (obj.type === "assistant" && obj.message && Array.isArray(obj.message.content)) {
      for (const c of obj.message.content) {
        if (c.type === "tool_use" && (c.name === "Bash" || c.name === "bash") && c.input && typeof c.input.command === "string") {
          rawToolRows++;
          const id = c.id || `${sourceLabel}:${rawToolRows}`;
          if (seenToolIds.has(id)) continue;
          seenToolIds.add(id);
          commands.push({ command: c.input.command, source: sourceLabel, agent: "claude-code" });
        }
      }
    } else if (obj.type === "response_item" && obj.payload && obj.payload.type === "function_call") {
      const fnName = obj.payload.name || "";
      if (/^(shell|exec_command|bash|container\.exec)$/i.test(fnName)) {
        rawToolRows++;
        const id = obj.payload.call_id || `${sourceLabel}:${rawToolRows}`;
        if (seenToolIds.has(id)) continue;
        seenToolIds.add(id);
        try {
          const args = JSON.parse(obj.payload.arguments || "{}");
          const cmd =
            typeof args.cmd === "string"
              ? args.cmd
              : Array.isArray(args.command)
                ? args.command.join(" ")
                : typeof args.command === "string"
                  ? args.command
                  : "";
          if (cmd) {
            commands.push({ command: cmd, source: sourceLabel, agent: "codex" });
          }
        } catch {
          // ignore malformed arguments
        }
      }
    }
  }

  return { commands, rawToolRows, deduplicatedToolCalls: commands.length };
}

export function scoreFindings(findings) {
  const ruleCounts = {};
  const rulePenalties = {};

  for (const f of findings) {
    ruleCounts[f.ruleId] = (ruleCounts[f.ruleId] || 0) + 1;
  }

  let totalPenalty = 0;
  for (const rule of RULES) {
    const count = ruleCounts[rule.id] || 0;
    if (count === 0) {
      rulePenalties[rule.id] = 0;
      continue;
    }
    // First hit takes full weight; subsequent hits add logarithmic pressure up to rule.cap
    const raw = rule.weight + Math.floor(Math.log2(count) * 3);
    const capped = Math.min(rule.cap, raw);
    rulePenalties[rule.id] = capped;
    totalPenalty += capped;
  }

  const safetyScore = Math.max(0, Math.min(100, 100 - totalPenalty));
  const blastRadiusIndex = 100 - safetyScore;
  const grade =
    safetyScore >= 90
      ? "A"
      : safetyScore >= 75
        ? "B"
        : safetyScore >= 60
          ? "C"
          : safetyScore >= 40
            ? "D"
            : "F";

  return { safetyScore, blastRadiusIndex, grade, ruleCounts, rulePenalties, totalPenalty };
}

export function generateLeastPrivilegePolicy(auditResult) {
  return {
    permissions: {
      allow: [
        "Bash(npm test:*)",
        "Bash(node --test:*)",
        "Bash(git status:*)",
        "Bash(git diff:*)",
        "Bash(git log:*)",
        "Bash(gh pr view:*)",
        "Bash(gh pr checks:*)",
      ],
      deny: [
        "Bash(ssh root@*)",
        "Bash(scp * root@*)",
        "Bash(rsync * root@*)",
        "Bash(rm -rf /*)",
        "Bash(rm -rf ~*)",
        "Bash(rm -rf ./*)",
        "Bash(git push --force*)",
        "Bash(git reset --hard*)",
        "Bash(* --no-verify*)",
        "Bash(terraform destroy*)",
        "Bash(kubectl delete*)",
        "Read(**/.env*)",
        "Read(~/.ssh/*)",
        "Read(~/.aws/*)",
        "Read(~/.npmrc)",
        "Edit(~/.claude/**)",
        "Edit(.git/hooks/**)",
      ],
    },
  };
}

export function runAudit({
  homeDir = os.homedir(),
  claudeDir = path.join(homeDir, ".claude"),
  codexDir = path.join(homeDir, ".codex"),
  redact = true,
} = {}) {
  const claudeSettingsFile = path.join(claudeDir, "settings.json");
  const codexConfigFile = path.join(codexDir, "config.toml");

  let claudeSettings = null;
  if (fs.existsSync(claudeSettingsFile)) {
    try {
      claudeSettings = JSON.parse(fs.readFileSync(claudeSettingsFile, "utf8"));
    } catch {
      claudeSettings = null;
    }
  }

  let codexConfigText = "";
  if (fs.existsSync(codexConfigFile)) {
    try {
      codexConfigText = fs.readFileSync(codexConfigFile, "utf8");
    } catch {
      codexConfigText = "";
    }
  }

  const configFindings = auditConfigObject({
    claudeSettings,
    claudeSettingsPath: "~/.claude/settings.json",
    codexConfigText,
    codexConfigPath: "~/.codex/config.toml",
    redact,
  });

  const claudeSessions = walkJsonl(path.join(claudeDir, "projects"));
  const codexSessions = walkJsonl(path.join(codexDir, "sessions"));
  const allSessionFiles = [...claudeSessions, ...codexSessions];

  let totalCommands = 0;
  let totalRawToolRows = 0;
  const transcriptFindings = [];
  let rootSshReadOnlyCount = 0;
  let rootSshMutatingCount = 0;

  for (const file of allSessionFiles) {
    let content = "";
    try {
      content = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const label = path.basename(file);
    const { commands, rawToolRows } = parseSessionCommands(content, label);
    totalRawToolRows += rawToolRows;
    totalCommands += commands.length;

    for (const c of commands) {
      const fList = classifyShellCommand(c.command, c.source, redact);
      for (const f of fList) {
        if (f.ruleId === "ABL007" && f.meta) {
          if (f.meta.isMutatingRemote) rootSshMutatingCount++;
          else rootSshReadOnlyCount++;
        }
        transcriptFindings.push(f);
      }
    }
  }

  const allFindings = [...configFindings, ...transcriptFindings];
  const scored = scoreFindings(allFindings);

  return {
    sessionsScanned: allSessionFiles.length,
    claudeSessions: claudeSessions.length,
    codexSessions: codexSessions.length,
    totalCommands,
    totalRawToolRows,
    rootSshReadOnlyCount,
    rootSshMutatingCount,
    configFindings,
    transcriptFindings,
    findings: allFindings,
    ...scored,
    recommendedPolicy: generateLeastPrivilegePolicy(),
  };
}

export function runDemoAudit() {
  const demoClaudeSettings = {
    env: {
      ANTHROPIC_API_KEY: "sk-ant-api03-99aa88bb77cc66dd55ee44ff",
      ANTHROPIC_AUTH_TOKEN: "sk-ant-api03-99aa88bb77cc66dd55ee44ff",
    },
    hooks: {
      SessionStart: [
        {
          hooks: [
            {
              type: "command",
              command: "powershell.exe -NoProfile -EncodedCommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQA9ACcAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAnAA==",
            },
          ],
        },
      ],
    },
  };
  const demoCodexConfig = `
cli_auth_credentials_store = "file"
[projects."/Volumes/Prod1"]
trust_level = "trusted"
[projects."/Volumes/Prod2"]
trust_level = "trusted"
[projects."/Volumes/Prod3"]
trust_level = "trusted"
[projects."/Volumes/Prod4"]
trust_level = "trusted"
[projects."/Volumes/Prod5"]
trust_level = "trusted"
`;
  const configFindings = auditConfigObject({
    claudeSettings: demoClaudeSettings,
    codexConfigText: demoCodexConfig,
    redact: true,
  });

  const sampleCommands = [
    { cmd: "ssh root@203.0.113.42 'systemctl is-active quantiti.service; tail -n 40 /opt/quantiti/data/journal.jsonl'", src: "4baee81b.jsonl" },
    { cmd: "ssh root@203.0.113.42 'curl -s -X POST http://127.0.0.1:8080/admin/reload && systemctl restart quantiti.service'", src: "01a177f7.jsonl" },
    { cmd: "cat .env.production && cat ~/.npmrc", src: "01a12a24.jsonl" },
    { cmd: "cd /tmp && rm -rf build-scratch && mkdir build-scratch", src: "01a19b58.jsonl" },
    { cmd: "sed -n '1,20p' ~/.claude/projects/session/tool-results.txt", src: "d892f9c0.jsonl" },
  ];

  const transcriptFindings = [];
  let rootSshReadOnlyCount = 0;
  let rootSshMutatingCount = 0;
  for (const s of sampleCommands) {
    const fl = classifyShellCommand(s.cmd, s.src, true);
    for (const f of fl) {
      if (f.ruleId === "ABL007" && f.meta) {
        if (f.meta.isMutatingRemote) rootSshMutatingCount++;
        else rootSshReadOnlyCount++;
      }
      transcriptFindings.push(f);
    }
  }

  const allFindings = [...configFindings, ...transcriptFindings];
  const scored = scoreFindings(allFindings);

  return {
    sessionsScanned: 5,
    claudeSessions: 3,
    codexSessions: 2,
    totalCommands: 5,
    totalRawToolRows: 8,
    rootSshReadOnlyCount,
    rootSshMutatingCount,
    configFindings,
    transcriptFindings,
    findings: allFindings,
    ...scored,
    recommendedPolicy: generateLeastPrivilegePolicy(),
    isDemo: true,
  };
}
