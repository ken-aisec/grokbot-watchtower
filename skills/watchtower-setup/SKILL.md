---
name: watchtower-setup
description: First-run setup for Watchtower. After the owner's one yes it installs the pinned, checksummed scripts and scanners into /workspace/watchtower, takes a baseline, plants three decoy files, runs the first audit, switches on the three routines and builds the first report. Use once after adding the template, when the scripts are missing, or to update Watchtower.
---

# Watchtower setup (about 7 minutes, one yes)

The owner's first yes covers everything in sections 1 to 4: the install, the six scanners, the three decoys and the three routines. Your first message listed all of it. Do not ask again for any of those; work through them and post a short progress line every minute or two. If the owner left something out ("no decoys", "no routines"), skip that part and say so at the end.

Say once, up front: "Setup only writes inside /workspace/watchtower, plus three decoy files in /tmp and /var/tmp."

## 1. Install the pinned release
Skip this section if `/workspace/watchtower/app/watchtower/wt.py` already exists and `wt.py --version` prints 0.6.7.
```bash
mkdir -p /workspace/watchtower && cd /workspace/watchtower
curl -fsSLO https://raw.githubusercontent.com/ken-aisec/grokbot-watchtower/v0.6.7/scripts/install.sh
head -30 install.sh
```
Show the user those 30 lines (they are everything that runs), then run `bash install.sh v0.6.7`, adding the commit ID if your Setup check memory gives one. Watchtower never pipes a script into a shell, and neither should anything it vets. If it prints MANIFEST CHECK FAILED or COMMIT CHECK FAILED, stop and report it.

Your skills are the SKILL.md files under `/workspace/watchtower/app/skills/`. Don't copy them anywhere; read them from there, so they always match the installed release. They are not slash commands: the owner asks in plain words.

## 2. Scanners
Run `bash /workspace/watchtower/app/scripts/install.sh --scanners`. Each tool installs on its own from a checksum lock; if one says it did not install, carry on. Watchtower works without it and the audit says which is missing. If it ends with `CHECKSUM LOCK FAILED`, the Python scanners were skipped and nothing was installed without checksums (gitleaks, TruffleHog and OSV-Scanner still installed from their own): tell the owner the reason it printed and carry on; never install the scanners another way.

## 3. Baseline, decoys, first audit
1. `python3 /workspace/watchtower/app/watchtower/wt.py baseline`
2. `wt.py canary plant`. It picks new random folder and file names for this computer. Tell the owner the three paths it prints, in this chat only; never write them into a memory, a skill, a routine, a file or another Bot's chat. Never open, list or search those files or their folders yourself, now or later: a read by you looks the same as a read by an intruder.
3. `wt.py audit`. Summarize in five lines: score, counts by severity, the top three fixes.

## 4. Routines
The routines usually arrive with the template, paused: daily watch (06:00), weekly audit and report (Sunday 05:00), weekly tidy (Sunday 06:00), in the account's time zone. Don't ask about the time zone. Switch those three on, or tell the user to flip the three switches under your Details tab if you can't. The monthly roll-call reminder stays off: roll-call is opt-in, and it is switched on only if the owner asks for it. If a routine is missing, create it from the matching file in `/workspace/watchtower/app/routines/`.

## 5. Tune it (the second and last question)
A first audit always includes things the user installed on purpose. Read `/workspace/watchtower/app/skills/watchtower-fix/SKILL.md` and follow it exactly: one message, one yes. After the yes, give the tuned score and say this is the starting line the weekly report compares against.

## 6. Ask-first rules (only the owner can add these)
You can't change app settings. Never say or imply that you will add these rules. Tell the owner: "In Grok Bot's settings, open Auto-review (it may be called Custom Rules) and add three Ask-first rules":
- Ask first before sending any external email or message
- Ask first before publishing, posting, purchasing, or deleting anything
- Ask first before creating, changing or switching on routines, or changing settings, permissions, or connectors

Once they say the rules are in, save the same three lines, each starting with `Ask first:`, to `/workspace/watchtower/exports/auto-review.txt` so Watchtower can see them, and run `wt.py audit`. Never write that file before the rules exist. These rules will also pause some of your own commands; when that happens the owner sees an approval card. That is the rules working.

## 7. First report, then finish
1. Read the watchtower-brief skill and run it once so the user sees it.
2. `wt.py report` (builds `/workspace/watchtower/reports/dashboard.html`).
3. Run the Validate checks below. Setup is not finished until they pass; if one fails, say which.

End with one message: what is on, the score, how many minutes it took, and the one or two things only the owner can do (usually the Ask-first rules and signing out of sites in the Bot browser; say plainly that the score stays where it is until they do). Ask once: "Should the weekly report also go somewhere fixed, such as one Slack channel or one email address? If you name it now, your yes covers that one place each week; otherwise I'll ask for approval each time." Only if the owner names one, save it as your "Report destination" memory, exactly as they wrote it, and send a test only on their yes. Then offer once: "Want a roll-call? It sends each of your other Bots one fixed question about its routines and memories. The replies are analyzed and deleted, and it doesn't change the score." Run it only on their yes, following the roll-call skill.

## If anything goes wrong
Watchtower prints one plain line starting with ERROR, never a stack trace. Run `wt.py doctor --save` and tell the user where the file is: it has no file contents, keys or skill names, and they can send it to the template's author.

## Validate
Run all of these before you say setup is done:
- `wt.py daily` twice: the second prints NO_CHANGES.
- `wt.py canary status` prints CANARIES_QUIET, or one low "bulk reader" line (the platform's file backup reads new files once; that is expected and is not an alarm).
- `ls /workspace/watchtower/reports/` shows dashboard.html and a threat-brief HTML file.

## Approval needed
The first yes covers scanners, decoys and routines. Anything else outside /workspace/watchtower needs its own yes: messages to other Bots, moving a skill into quarantine, removing anything. If Auto-review blocks or pauses a command, stop and ask the owner; never reword the command to get it through.
