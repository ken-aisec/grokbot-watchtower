---
name: watchtower-fix
description: The one-yes fix. Cleans up, upgrades outdated software (undoing any upgrade that breaks something), sets the Ask-first rules, and accepts findings that are fine on purpose, after asking the user a single question. Use when the user says fix it, fix everything, clean up, or runs the weekly tidy.
---

# Fix everything with one yes

1. Run `python3 /workspace/watchtower/app/watchtower/wt.py audit`, then `wt.py fix`. The second command is a preview and changes nothing. Its JSON has `safe_fixes`, `upgrades`, `decisions`, `ask_first_rules_missing` and `only_you`.

2. Post ONE message, at most 12 lines, in this order. Plain words, no rule IDs:
   - **Doing now:** the safe cleanup in one line (for example "remove 3 old keys from 2 chats, empty 2 tool caches, reset the decoys").
   - **Upgrading:** the Python packages and project names from `upgrades`. Say "I undo any upgrade that breaks something."
   - **Ask-first rules:** if `ask_first_rules_missing`, say you'll add the three Ask-first rules (sending messages; publishing, posting, buying or paying; changing settings, routines or connectors).
   - **Fine on purpose?** each entry in `decisions` as one line: what it is, how many, and up to six names. Say "I'll accept these for 90 days; new ones will still show up."
   - **Only you:** each `only_you` item with its link. Keys that still work can only be turned off by the user at the provider.
   Then ask: "Reply yes to do all of it, or tell me what to skip."

3. On yes (or yes with exceptions):
   - If Ask-first rules were missing, add the three rules in Settings → General → Auto-review, then save the same rules, one per line starting with `Ask first:`, to `/workspace/watchtower/exports/auto-review.txt` so Watchtower can see them.
   - Run `wt.py fix --apply --upgrade --accept <the decision rules the user agreed to, comma-separated> --reason "reviewed by owner"`. Leave out any rule the user said to skip. Leave out `--upgrade` if they said to skip upgrades.
   - Run `wt.py audit`.

4. Reply in at most 6 lines: what was done (the `done` list in plain words), the new score and the change, and anything still in `only_you`. If an upgrade was undone or skipped, say which and why.

## Never
- Turn off or revoke a key. Show the link and let the user do it.
- Use `--force` with npm, or touch node_modules, or change package.json. The fix only updates lockfiles and keeps a backup.
- Accept anything the command refuses. It refuses two scanners agreeing a skill is dangerous, a decoy being touched, a working key, and a memory acting as an order.
- Print a key, even partly.
- Run `--upgrade` or `--accept` without the user's yes in this conversation. The weekly tidy routine runs only the safe cleanup.
