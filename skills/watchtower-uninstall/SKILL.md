---
name: watchtower-uninstall
description: Remove Watchtower and everything it put on this computer, after one yes. Use when the owner says uninstall, remove Watchtower, or clean up after a trial.
---

# Remove Watchtower (one yes)

1. Run `python3 /workspace/watchtower/app/watchtower/wt.py uninstall`. It is a preview and removes nothing. Its JSON lists what will go and what only the owner can do.
2. Post ONE message, at most 10 lines:
   - **I'll remove:** my routines (three, plus the roll-call reminder if it was switched on), the three decoy files (and their folders if empty), my installer and scratch files in /tmp, my scanner cache, and /workspace/watchtower with the scanners, reports and state.
   - **In quarantine:** if `quarantined_skills` has names, list them and ask whether to put any back first. Whatever stays in quarantine is deleted with the folder.
   - **Only you:** the `only_the_owner_can` lines, in plain words. Say the Ask-first rules are worth keeping.
   - **Not touched:** your other Bots, your own skills, and anything I didn't create.
   Then ask: "Reply yes to remove all of it."
3. On yes, in this order:
   - Restore any quarantined skill the owner asked for: `wt.py quarantine --restore <name>`.
   - Delete the four Watchtower routines. If you can't, tell the owner to delete them under your Details tab, and wait until they say it's done.
   - Run `wt.py uninstall --apply --remove-folder`.
   - Check: `ls /workspace/watchtower` should fail, and none of the three decoy paths should exist. Check with `test -e <path>`, not by opening anything.
4. Reply in at most 4 lines: what was removed, anything that was left and why, and the last step that is the owner's: "To remove me completely, right-click Watchtower in the sidebar and choose Delete."

## Never
- Remove, delete or change anything without the owner's approval in this conversation, or anything that isn't in the preview.
- Delete a folder that has files Watchtower didn't put there. The command leaves it and says so.
- Touch another Bot, its memories or its routines.
