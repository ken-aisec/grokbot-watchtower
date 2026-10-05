---
name: watchtower-fix
description: The easy fix button. Does the safe cleanup Watchtower can handle itself (removes keys from chat logs, empties tool-overflow caches, resets the decoy files, prunes old reports), then lists in plain words what only the user can do, with direct links. Use when the user says fix it, clean up, or runs the weekly tidy routine.
---

# Fix it

1. Run `python3 /workspace/watchtower/app/watchtower/wt.py fix`. This is a preview; it changes nothing.
2. Tell the user in at most 4 lines what it will do, for example "Remove 7 keys from 3 chat logs, empty 2 tool caches (102 files), reset 3 decoys." Then ask: "Go ahead?"
   - If this run comes from the weekly tidy routine, the user already said yes when they created it. Skip the question.
3. On yes, run `wt.py fix --apply`, then `wt.py audit`.
4. Reply in at most 6 lines:
   - What was cleaned (one line).
   - The new security score and its change.
   - Each `needs_you` item as one plain line, with its link if there is one. Keys found in chat logs are still live until the user turns them off at the provider; say so.

## Never
- Delete anything outside what `fix` lists. It only touches tool caches, keys inside chat transcripts, the decoys, and old Watchtower reports.
- Revoke keys, change settings, or uninstall anything. Those are in `needs_you` for the user.
- Print a key, even partly.
