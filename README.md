# Watchtower — Security Watch for Grok Bot

Every Grok Bot on your account shares one cloud computer: the same browser logins, files and command-line credentials. xAI's own docs say not to treat separate Bots as a security boundary. When you add a template, its skills and routines run with everything your other Bots are signed into, and audit logs, network allowlists and the MCP allowlist are Enterprise-only.

Watchtower is a read-only security officer for that setup. It vets templates before you install them, audits your computer and every Bot on it, sets tripwires, sends a weekly threat brief, and tells you the few fixes that matter.

## What it does

| Skill | What you get |
| --- | --- |
| `/vet-template` | Install / Install with changes / Do not install for any template, skill or plugin, with a risk score, evidence, its autonomy level (L0 observe → L3 unattended), and the boundary line to paste into its description |
| `/watchtower-audit` | A 0–100 posture score and the top three fixes across skills, plugins, MCP configs, Auto Review rules, local execution, logged-in browser sessions, CLI credentials, secrets, vulnerable packages, persistence, integrity drift, canaries and shell history |
| `/watchtower-brief` | The weekly report, one page you can read in a minute: status, score, threat level, trend charts, a one-click fix, what needs you, and the three threats that matter to your setup |
| `/watchtower-report` | Weekly Markdown report and a self-contained HTML dashboard |
| `/watchtower-rollcall` | DMs every Bot for its routines, connectors and stored memories, then flags poisoned memories, unsafe routines and the lethal trifecta (private data + untrusted input + a way out) |
| `/watchtower-prepublish` | PASS/FAIL before you share a Bot as a template: secrets, emails, phone numbers, private doc links, internal hosts, local paths, and a missing approval boundary |
| `/watchtower-incident` | Evidence pack first (findings, canaries, changed files, history, processes, connections, jobs), then containment one approved step at a time |
| `/watchtower-codescan` | OWASP Top 10 (2021) review of code your Bots write, plus semgrep if installed |
| `/watchtower-fix` | The one-yes fix: cleans up, upgrades outdated Python packages and npm lockfiles (each upgrade is backed up and undone automatically if it breaks something), adds your Ask-first rules, and accepts findings that are fine on purpose, after asking you a single question |
| `/watchtower-setup` | Pinned, checksummed install; scanners; canaries; first audit and report; routines |

| Routine | When | Cost |
| --- | --- | --- |
| Daily watch | 06:00 | Silent unless something changed. Scripts only; the model reads a delta under 4 KB. |
| Weekly audit and report | Sunday 05:00 | One audit, one report, one summary. |
| Weekly tidy | Sunday 06:00 | Runs the safe fixes without asking; posts one line. |
| Monthly roll-call | 1st of the month | One DM per Bot. |

Every finding carries a rule ID, severity, file and line (secrets masked), the fix, and a mapping to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (ASI), the [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) (AST), or the OWASP Top 10 (2021) for code.

## Three engines, one verdict

Skills are checked by Watchtower's own rules, [NVIDIA SkillSpector](https://github.com/nvidia/skillspector) and [husk](https://github.com/ctrl-adam/Husk). A skill flagged by one engine is a lead. A skill flagged by two is a corroborated critical. Your own skills, and any skill that's new or changed, get all three every day; marketplace and first-party skills are checked for malicious indicators, not style. gitleaks finds keys left in files and TruffleHog checks which of them still work, so you only revoke the live ones. pip-audit and OSV-Scanner cover known holes in installed software and project dependencies. The weekly report says which scanners checked your setup.

## Tripwires

`wt.py canary plant` places three decoys (a fake customer export, fake cloud keys, a fake payments .env). Nothing legitimate reads them. If anything opens, deletes or copies one, the next daily run says so. Zero tokens, and the best early warning a non-Enterprise account can get.

## How it stays light

Scripts find, the model judges, you approve. Scanning is deterministic Python with no dependencies of its own. A daily run with nothing new prints `NO_CHANGES` and the Bot stops without reading anything.

## Install (in Grok Bot)

1. Add the Watchtower template from its x.ai link.
2. Run `/watchtower-setup`.

Manual install on the cloud computer:

```bash
mkdir -p /workspace/watchtower && cd /workspace/watchtower
curl -fsSLO https://raw.githubusercontent.com/ken-aisec/grokbot-watchtower/v0.5.2/scripts/install.sh
head -40 install.sh && bash install.sh v0.5.2
bash /workspace/watchtower/app/scripts/install.sh --scanners
python3 /workspace/watchtower/app/watchtower/wt.py audit
```

## CLI

```
wt.py vet FILE|-              vet before installing (exit 1 = Do not install)
wt.py audit | daily           full or quick audit (compact JSON for the Bot)
wt.py report                  weekly report + dashboard.html
wt.py brief [--summary F]     weekly threat brief (HTML)
wt.py rollcall                analyze saved roll-call replies
wt.py prepublish PATH         check a Bot before sharing it as a template
wt.py fix [--apply]            safe cleanup (preview by default)
wt.py fix --apply --upgrade --revet --accept RULES   everything in one pass (after your yes)
wt.py diff SKILL               what changed in a skill since you approved it
wt.py exception add SKILL --reason "..."   keep one named security-tool skill that two scanners flag (30 days)
wt.py accept RULE WHERE --reason "..."   accept one risk on purpose (90 days)
wt.py accept --all-current RULES         accept everything currently open for those rules
wt.py events list|clear        one-time detections
wt.py canary plant|status|remove
wt.py incident --note "..."   evidence pack + containment checklist
wt.py codescan PATH           OWASP Top 10 code review
wt.py status                  what a running audit is doing and how long each stage took
wt.py breakdown | show RULE   findings by rule; evidence with context
wt.py baseline                accept current skills as reviewed
```

State lives in `$WATCHTOWER_HOME` (default `/workspace/watchtower`). `state/ledger.jsonl` is an append-only record of every run: the audit trail non-Enterprise accounts don't get.

## Limits, stated plainly

- It audits after the fact. It can't intercept another Bot's actions in real time; Auto Review is the inline control, and Watchtower checks how you've set it up.
- Static engines can be bypassed. Three independent engines, hash drift, tripwires and history review make that harder, and the reports say they're evidence, not proof.
- Roll-call relies on each Bot describing itself. A compromised Bot could lie, which is why the filesystem evidence comes first.
- Canary reads need a filesystem that records access times; setup tells you if yours doesn't.
- Grok Bot is in beta and changes weekly. The brief watches xAI's security docs for changes.

## Tests

`make test` runs 61 tests: seeded malicious skills must be caught, clean and defensive text must not be flagged, hostile feed content must not execute in the brief, and every feature has its own test.

## License

Apache-2.0. See `THREAT_MODEL.md`, `EGRESS.md` and `SECURITY.md`.
