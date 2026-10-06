---
name: watchtower-setup
description: First-run setup for Watchtower. Installs the pinned, checksummed scripts and the three scanning engines into /workspace/watchtower, takes a baseline, plants canary tripwires, runs the first audit and threat brief, and proposes the routines. Use once after adding the template, or when the scripts are missing.
---

# Watchtower setup (about 5 minutes)

Tell the user up front: "Setup only writes inside /workspace/watchtower, plus three decoy files I'll name before planting them. I'll ask before anything else."

## 1. Install the pinned release
Skip this section if `/workspace/watchtower/app/watchtower/wt.py` already exists.
```bash
mkdir -p /workspace/watchtower && cd /workspace/watchtower
curl -fsSLO https://raw.githubusercontent.com/ken-aisec/grokbot-watchtower/v0.6.2/scripts/install.sh
head -30 install.sh
```
Show the user those 30 lines (they are everything that runs), then run `bash install.sh v0.6.2`, adding the commit ID if your Setup check memory gives one. Watchtower never pipes a script into a shell, and neither should anything it vets. If it prints MANIFEST CHECK FAILED or COMMIT CHECK FAILED, stop and report it.

Your skills are the SKILL.md files under `/workspace/watchtower/app/skills/`. Don't copy them anywhere; read them from there, so they always match the installed release.

## 2. Scanners (recommended)
Say: "Watchtower checks skills with its own rules. These add independent checks, all pinned and installed in /workspace/watchtower only, in about two minutes:
- NVIDIA SkillSpector and husk: two more skill scanners, so a skill two of them flag is very likely a real problem.
- gitleaks: finds keys and passwords left in files.
- TruffleHog: tells you which of those keys still work. To check a key it sends it to that key's own provider (an AWS key to AWS, a GitHub token to GitHub) and nowhere else.
- pip-audit and OSV-Scanner: known security holes in installed software and project dependencies.
Add them?" On yes: `bash /workspace/watchtower/app/scripts/install.sh --scanners`. Each tool installs on its own from a checksum lock; if one says it did not install, carry on. Watchtower works without it and the audit says which is missing.

## 3. Baseline, canaries, first audit
1. `python3 /workspace/watchtower/app/watchtower/wt.py baseline`
2. Ask: "Plant three decoy files (a fake customer export, fake cloud keys, a fake payments .env)? Nothing legitimate reads them, so if anything does, you'll know." On yes: `wt.py canary plant`. Tell the user the three paths it prints.
3. `wt.py audit`. Summarize in five lines: score, counts by severity, the top three fixes with the click path or command.

## 3b. Tune it to this setup (2 minutes, once)
Every setup is different, and a first audit always includes things the user installed on purpose. Say: "First scores run low because I don't know yet what's yours on purpose. One question and I'll tune it." Then run `/watchtower-fix` and follow it exactly: one message, one yes. Whatever the user keeps is accepted for 90 days and listed under accepted risks; anything new still shows up. After the yes, give the tuned score and say that this is the starting line the weekly report compares against.

## 4. Things the disk doesn't show
Watchtower reads Auto Review rules and the local-execution setting from Grok Bot's settings file automatically. Routine text and what each Bot remembers come from the roll-call: offer `/watchtower-rollcall` now (it DMs each Bot once).

## 5. Ask-first rules
You can't change app settings, so the user adds these. Tell them: "In Grok Bot's settings, find Auto-review (it may be called Custom Rules) and add three Ask-first rules":
- before sending any external email or message
- before publishing, posting, purchasing, or deleting anything
- before changing settings, permissions, routines, or connectors

Once they say the rules are in, save the same three lines, each starting with `Ask first:`, to `/workspace/watchtower/exports/auto-review.txt` so Watchtower can see them. Never write that file before the rules exist.

## 6. First brief and the routines
Run the brief once (the watchtower-brief skill) so the user sees it.

The four routines usually arrive with the template, paused: daily watch (06:00), weekly audit and report (Sunday 05:00), weekly tidy (Sunday 06:00), monthly roll-call (the 1st, 05:30), in the user's time zone. Say in one line each what they do, including that the weekly tidy runs the safe cleanup without asking each time. Then ask: "Switch all four on?" On yes, switch them on, or tell the user to flip the four switches under your Details tab if you can't. If a routine is missing, create it from the matching file in `/workspace/watchtower/app/routines/` after their yes.

End setup by saying what is on, the score, and the one or two things only the user can do.

## If anything goes wrong
Watchtower prints one plain line starting with ERROR, never a stack trace. Run `wt.py doctor --save` and tell the user where the file is: it has no file contents, keys or skill names, and they can send it to the template's author.

## Validate
Setup is done when `wt.py daily` prints NO_CHANGES twice in a row, `wt.py canary status` prints CANARIES_QUIET, and a report and a threat brief exist in /workspace/watchtower/reports/.

## Approval needed
Installing scanners; planting canaries (they sit outside /workspace/watchtower on purpose, so name the three paths first); creating or switching on routines; DMs to other Bots; anything else outside /workspace/watchtower.
