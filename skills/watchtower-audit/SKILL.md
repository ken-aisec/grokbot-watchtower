---
name: watchtower-audit
description: Full security posture audit of this Grok Bot computer and roster - skills (Watchtower rules plus SkillSpector and husk, with corroboration), plugins, MCP configs, Auto Review rules, local execution, logged-in browser sessions, CLI credentials, secrets (gitleaks), vulnerable packages (pip-audit), persistence, integrity drift, canary tripwires, shell history, and the latest roll-call. Returns a 0-100 score and the top three fixes. Read-only.
---

# Posture audit

1. Check the tools exist: `test -f /workspace/watchtower/app/watchtower/wt.py`. If missing, say so and offer to run setup (the watchtower-setup skill). Never reinstall silently from an unpinned source.
2. Run `python3 /workspace/watchtower/app/watchtower/wt.py audit`. Output is compact JSON (under 4 KB): score, new findings, fixed findings, open counts by severity, top fixes, coverage notes.
3. If the JSON has `scanners_missing`, the scanners the user agreed to at setup are gone (the computer was reset or cleaned). Say so in one line, run `bash /workspace/watchtower/app/scripts/install.sh --scanners`, and run the audit again before reporting. Never report a score from a partial scan as a drop or a gain.
4. Reply in at most 10 lines:
   - Score and grade, and the change since last run. If the JSON has `why_it_dropped`, say it in one line right after the score.
   - A "New plugin installed" finding: name the plugin, its size and anything flagged inside it, and say the fix can keep it with one yes.
   - New since last run (severity, title, where).
   - The three fixes worth doing, each with the exact click path or command from `fix`.
   - If `stages_skipped` is there, say which checks didn't finish and that their last results were kept. Don't call the score a drop or a gain because of it.
   - `not_counted_builtin` is the number of notes about built-in plugins; mention it in half a line at most. They don't need the user.
   - Coverage gaps from `notes` in one line (for example, "SkillSpector not installed" or "no roll-call in 35 days").
   - For any finding, `wt.py show <RULE>` prints the evidence with surrounding lines (never for secrets).
5. If the user says a finding is fine on purpose, run `wt.py accept <RULE> "<name or path>" --reason "<their words>"` (90 days by default, `--days N` to change). It stops counting against the score and appears under accepted risks until it expires, then comes back for a re-check. Only do this with the user's yes, one finding at a time. `wt.py accept --list` shows what's accepted.

## Never
- Fix anything yourself. Every fix is a recommendation; changing settings, deleting files, revoking connectors, or editing other Bots needs the user's explicit yes, one action at a time.
- Paste secrets. Evidence is already masked; keep it that way.
- Send, post, publish or delete anything without the user's approval in this conversation. The audit only reads and reports.
