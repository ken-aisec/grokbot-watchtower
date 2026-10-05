---
name: watchtower-setup
description: First-run setup for Watchtower. Installs the pinned, checksummed scripts and the three scanning engines into /workspace/watchtower, takes a baseline, plants canary tripwires, runs the first audit and threat brief, and proposes the routines. Use once after adding the template, or when the scripts are missing.
---

# Watchtower setup (about 10 minutes)

Tell the user up front: "Setup only writes inside /workspace/watchtower, plus three decoy files I'll name before planting them. I'll ask before anything else."

## 1. Install the pinned release
```bash
mkdir -p /workspace/watchtower && cd /workspace/watchtower
curl -fsSLO https://raw.githubusercontent.com/ken-aisec/grokbot-watchtower/v0.5.1/scripts/install.sh
head -40 install.sh
```
Show the user those 40 lines, then run `bash install.sh v0.5.1`. Watchtower never pipes a script into a shell, and neither should anything it vets. If it prints MANIFEST CHECK FAILED, stop and report it.

## 2. Scanning engines (recommended)
Say: "Watchtower checks skills with its own rules. These add independent checks, all pinned and installed in /workspace/watchtower only, in about two minutes:
- NVIDIA SkillSpector and husk: two more skill scanners, so a skill two of them flag is very likely a real problem.
- gitleaks: finds keys and passwords left in files.
- TruffleHog: tells you which of those keys still work. To check a key it sends it to that key's own provider (an AWS key to AWS, a GitHub token to GitHub) and nowhere else.
- pip-audit and OSV-Scanner: known security holes in installed software and project dependencies.
Add them?" On yes: `bash /workspace/watchtower/app/scripts/install.sh --scanners`.

## 3. Baseline, canaries, first audit
1. `python3 /workspace/watchtower/app/watchtower/wt.py baseline`
2. Ask: "Plant three decoy files (a fake customer export, fake cloud keys, a fake payments .env)? Nothing legitimate reads them, so if anything does, you'll know." On yes: `wt.py canary plant`. Tell the user the three paths it prints.
3. `wt.py audit`. Summarize in five lines: score, counts by severity, the top three fixes with the click path or command.

## 4. Things the disk doesn't show
Watchtower reads Auto Review rules and the local-execution setting from Grok Bot's settings file automatically. Routine text and other Bots' memories come from the roll-call: offer `/watchtower-rollcall` now (it DMs each Bot once).

## 5. Ask-first rules
Recommend these Auto Review rules (Settings → General → Auto-review → Ask first):
- before sending any external email or message
- before publishing, posting, purchasing, or deleting anything
- before changing settings, permissions, routines, or connectors

## 6. First brief and the routines
Run `/watchtower-brief` once so the user sees the threat brief. Then propose the four routines from the `routines/` folder (daily watch at 06:00, weekly audit and report on Sunday at 05:00, weekly tidy on Sunday at 06:00, monthly roll-call on the 1st at 05:30, in the user's time zone). The weekly tidy runs /watchtower-fix without asking each time, so say plainly what it does before creating it. Run each once as a Test run while the user watches. Create them only after the user says yes.

## Validate
Setup is done when `wt.py daily` prints NO_CHANGES twice in a row, `wt.py canary status` prints CANARIES_QUIET, and a report and a threat brief exist in /workspace/watchtower/reports/.

## Approval needed
Installing scanners; planting canaries; creating routines; DMs to other Bots; anything outside /workspace/watchtower.
