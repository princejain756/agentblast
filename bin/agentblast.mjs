#!/usr/bin/env node
import { RULES, RULE_MAP, runAudit, runDemoAudit } from "../src/analyzer.mjs";

const args = process.argv.slice(2);
const isDemo = args.includes("--demo");
const isJson = args.includes("--json");
const emitPolicy = args.includes("--emit-policy");
const showRules = args.includes("--rules");
const noRedact = args.includes("--no-redact");

const failUnderIdx = args.indexOf("--fail-under");
const failUnder = failUnderIdx !== -1 ? Number(args[failUnderIdx + 1]) : null;

if (args.includes("--help") || args.includes("-h")) {
  console.log(`agentblast v0.1.0 - Production Blast-Radius & Permission Auditor for Claude Code & Codex CLI

Usage:
  npx agentblast [options]

Options:
  --demo               Run on bundled multi-session production SSH & config fixture
  --emit-policy        Print a least-privilege .claude/settings.json permissions block
  --json               Output machine-readable JSON audit report
  --rules              List all 14 static config & transcript blast-radius rules (ABL001-ABL014)
  --fail-under <score> Exit with code 1 if Safety Score is below <score> (0-100)
  --no-redact          Disable automatic IPv4 and API token redaction in output
`);
  process.exit(0);
}

if (showRules) {
  console.log("AGENTBLAST v0.1.0 · Rule Catalog (ABL001-ABL014)");
  console.log("══════════════════════════════════════════════════════════════════════════════");
  for (const r of RULES) {
    console.log(`  [${r.id}] (${r.plane.toUpperCase()} · ${r.severity} · weight ${r.weight} / cap ${r.cap})`);
    console.log(`           ${r.title}`);
    console.log(`           Fix: ${r.fix}`);
  }
  process.exit(0);
}

const report = isDemo ? runDemoAudit() : runAudit({ redact: !noRedact });

if (emitPolicy) {
  console.log(JSON.stringify(report.recommendedPolicy, null, 2));
  process.exit(0);
}

if (isJson) {
  console.log(JSON.stringify(report, null, 2));
  if (failUnder !== null && report.safetyScore < failUnder) process.exit(1);
  process.exit(0);
}

function bar(val, max, width = 12) {
  const filled = max > 0 ? Math.min(width, Math.round((val / max) * width)) : 0;
  return "█".repeat(filled) + "░".repeat(width - filled);
}

console.log("AGENTBLAST v0.1.0 · Agent Production Blast-Radius & Permission Auditor");
console.log("══════════════════════════════════════════════════════════════════════════════");
console.log(
  `Target            : ${
    isDemo
      ? "bundled demo fixture (3 Claude Code + 2 Codex sessions)"
      : `~/.claude (${report.claudeSessions} sessions) + ~/.codex (${report.codexSessions} sessions)`
  }`
);
console.log(
  `Shell Replay      : ${report.totalCommands} deduplicated commands (${report.totalRawToolRows} raw JSONL rows)`
);
console.log(
  `Safety Score      : ${report.safetyScore}/100 (Grade ${report.grade}) · Blast-Radius Index: ${report.blastRadiusIndex}/100`
);
console.log(
  `Root/Remote SSH   : ${report.ruleCounts.ABL007 || 0} calls (${report.rootSshReadOnlyCount} read-only probes, ${report.rootSshMutatingCount} remote mutations)`
);
console.log("");
console.log("PLANE 1 · STATIC CONFIG & PERMISSION POLICY (~/.claude & ~/.codex)");
console.log("──────────────────────────────────────────────────────────────────────────────");
const configRules = RULES.filter((r) => r.plane === "config");
for (const r of configRules) {
  const count = report.ruleCounts[r.id] || 0;
  const pen = report.rulePenalties[r.id] || 0;
  console.log(
    `  [${r.id}] ${r.title.slice(0, 44).padEnd(44)} [${bar(pen, r.cap, 10)}] -${String(pen).padStart(2)}/${r.cap} pts (${count}x)`
  );
}

console.log("");
console.log("PLANE 2 · OBSERVED TRANSCRIPT BLAST-RADIUS REPLAY");
console.log("──────────────────────────────────────────────────────────────────────────────");
const transcriptRules = RULES.filter((r) => r.plane === "transcript");
for (const r of transcriptRules) {
  const count = report.ruleCounts[r.id] || 0;
  const pen = report.rulePenalties[r.id] || 0;
  console.log(
    `  [${r.id}] ${r.title.slice(0, 44).padEnd(44)} [${bar(pen, r.cap, 10)}] -${String(pen).padStart(2)}/${r.cap} pts (${count}x)`
  );
}

console.log("");
console.log("TOP REDACTED EVIDENCE & REMEDIATION");
console.log("──────────────────────────────────────────────────────────────────────────────");

// Show up to 1 sample per triggered rule sorted by severity weight
const seenRules = new Set();
const orderedFindings = [...report.findings].sort(
  (a, b) => (RULE_MAP[b.ruleId]?.weight || 0) - (RULE_MAP[a.ruleId]?.weight || 0)
);

for (const f of orderedFindings) {
  if (seenRules.has(f.ruleId)) continue;
  seenRules.add(f.ruleId);
  const r = RULE_MAP[f.ruleId];
  const totalForRule = report.ruleCounts[f.ruleId] || 1;
  console.log(`  [${f.ruleId}] (${r.severity} · ${totalForRule}x) ${f.source}`);
  console.log(`           ${f.detail}`);
  console.log(`           Fix: ${r.fix}`);
}

console.log("");
console.log("Run `npx agentblast --emit-policy` to generate a drop-in least-privilege .claude/settings.json block.");

if (failUnder !== null && report.safetyScore < failUnder) {
  process.exit(1);
}
