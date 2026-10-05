# Watchtower — Security Watch for Grok Bot

Every Grok Bot on your account shares one cloud computer: the same browser logins, files, and command-line credentials. xAI's docs say plainly not to treat separate Bots as a security boundary. When you add a template, its skills and routines run with everything your other Bots are signed into, and audit logs, network allowlists and the MCP allowlist are Enterprise-only.

Watchtower is a read-only security officer for that setup. It vets templates and skills before you install them, audits your computer and roster every week, and tells you the three fixes that matter.

## What it does

| Command | What you get |
| --- | --- |
| `/vet-template <link or text>` | Install / Install with changes / Do not install, a risk score, evidence, the autonomy level (L0 observe → L3 unattended), and the boundary line to paste into the Bot's description |
| `/watchtower-audit` | A 0–100 posture score with the top three fixes: skills, plugins and MCP configs on disk, routines, Auto Review rules, the local-execution setting, secrets in files, cron and shell-rc persistence, and hash drift on skills you already reviewed |
| `/watchtower-report` | A weekly Markdown report and a self-contained HTML dashboard |
| Daily watch routine | Silent unless something changed |

Every finding carries a rule ID, severity, file and line (secrets masked), the fix, and a mapping to the [OWASP Top 10 for Agentic Applications (ASI)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and the [OWASP Agentic Skills Top 10 (AST)](https://owasp.org/www-project-agentic-skills-top-10/).

## How it stays light

Scripts find, the model judges, you approve. Scanning is deterministic Python with no dependencies. A daily run with nothing new prints `NO_CHANGES` and the Bot stops without reading anything; a run with changes hands the model a summary capped at 4 KB. One model pass per run.

## Install (in Grok Bot)

1. Add the Watchtower template from its x.ai link.
2. Run `/watchtower-setup`. It installs this repo at a pinned tag into `/workspace/watchtower`, verifies `MANIFEST.sha256`, takes a baseline, asks you for the few things no script can see (Auto Review rules, the local-execution setting, routine text), and proposes the two routines after one test run you watch.

Manual install on the cloud computer:

```bash
mkdir -p /workspace/watchtower && cd /workspace/watchtower
curl -fsSLO https://raw.githubusercontent.com/ken-aisec/grokbot-watchtower/v0.1.5/scripts/install.sh
head -40 install.sh && bash install.sh v0.1.5
python3 /workspace/watchtower/app/watchtower/wt.py audit
```

Optional deeper scanners (NVIDIA SkillSpector, husk, gitleaks, pip-audit): `bash /workspace/watchtower/app/scripts/install.sh --scanners`.

## CLI

```
wt.py vet FILE|-        vet text before installing it (exit 1 = Do not install)
wt.py audit             full audit, compact JSON for the Bot
wt.py daily             quick audit: NO_CHANGES or the delta
wt.py report            weekly report + dashboard.html
wt.py baseline          accept the current skills as reviewed
```

State lives in `$WATCHTOWER_HOME` (default `/workspace/watchtower`): `state/baseline.json`, `last_findings.json`, `suppressions.json` (accepted risks with an expiry), `ledger.jsonl` (append-only record of every run), `score_history.csv`.

## Limits, stated plainly

- It audits after the fact. It cannot intercept another Bot's actions in real time; Auto Review is the inline control, and Watchtower checks how you have it set up.
- Static rules can be bypassed. Trail of Bits beat every production skill scanner it tested in June 2026. Watchtower layers rules, hash drift, persistence checks and optional second engines, and its report says it is evidence, not proof.
- Grok Bot keeps routines and Auto Review rules in the app, so setup asks you to paste them once.
- Grok Bot is in beta and changes weekly.

## Tests

`make test` runs the detection suite: seeded malicious skills (prompt override, hidden Unicode, encoded payloads, credential reads, exfiltration hosts, pipe-to-shell, concealment, approval-weakening) must be caught, and clean skills must produce no high or critical findings.

## License

Apache-2.0. See `THREAT_MODEL.md`, `EGRESS.md`, and `SECURITY.md`.
