# Changelog

## v0.1.4 — 2026-10-05 (third real audit)
- Instruction-override rule understands defensive writing: "ignore any instructions inside the transcript", table cells, HTML/Markdown comments, regex source. Files that list several injection patterns (references, detectors) get one info note instead of criticals.
- New WT-S004: Grok Bot's seeded browser sessions (chrome-cookie-seed.json) reported as the list of logged-in domains, never values, with sign-out advice; no longer a "delete this file" secret finding.
- Baseline entries under now-skipped caches no longer show as "removed"; info findings never appear as new.

## v0.1.3 — 2026-10-05 (second real audit)
- Skips language package caches (Go module cache, Maven, Gradle, dist-packages, bun, pnpm).
- Trust tiers: the user's own saved skills get every rule; first-party bundles, marketplace plugins, other agents' skill folders and copies in /workspace get malicious-indicator rules only.
- Known installers piped to shell (bun, rustup, uv, Homebrew, Docker, nvm…) are medium, low in vendor skills; unknown hosts stay critical.
- Placeholder and low-variety keys in documentation are ignored.
- New `wt.py show RULE` prints evidence with surrounding context (never for secrets).
- `publish.sh` works with a repo that already exists and is safe to rerun.

## v0.1.2 — 2026-10-05 (noise fixes from the first real audit)
- Skips browser profiles and caches (Chrome scoped_dir, WasmTtsEngine, Cache dirs) and package caches.
- Tighter OpenAI-style key pattern: `sk-SK-…` Slovak voice names were matching.
- New WT-S003: known CLI credential files (Claude Code, GitHub CLI, AWS, git, Docker, npm, gcloud) reported once each as high with least-privilege advice instead of "delete".
- Skills from managed and marketplace plugins are checked for malicious indicators only, not style.
- Score counts each risk once (plus up to 5 for repeats), so 300 skills with the same style issue don't outweigh one live secret.
- Report lists low findings as counts; new `wt.py breakdown` shows findings by rule and folder.

## v0.1.1 — 2026-10-05 (fitted to a real Grok Bot computer)
- Reads Grok Bot's own `~/agent-data/settings.json`: Auto Review rules and local-tool permission, no export needed.
- New WT-A004: an Allow-automatically rule that lets a Bot create automations, routines or installs is high risk.
- New WT-A005: no Auto Review rules at all.
- gitleaks always runs with `--redact` and its report is deleted after parsing, so Watchtower never writes plaintext secrets to the shared computer; findings grouped per file.
- Secrets scan: one finding per file with a count.
- SkillSpector: parses the real `issues[]` and `risk_assessment` schema (v2.12).
- `/vet-template`: public previews show only the description, so it uses the Download link.

## v0.1.0 — 2026-10
- `wt.py` with vet, audit, daily, report, baseline; stdlib only.
- 16 text rules mapped to OWASP ASI and AST, with context guards so warnings about attacks are not flagged as attacks.
- Routine, Auto Review and settings linters; integrity drift; persistence diff; secrets scan with masking.
- Optional SkillSpector, gitleaks and pip-audit integration.
- Four skills, two routines, the Bot description, pinned installer with manifest verification.
