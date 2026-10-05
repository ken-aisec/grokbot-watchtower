---
name: watchtower-audit
description: Full security posture audit of this Grok Bot computer and roster - skills, plugins, MCP configs, routines, Auto Review rules, local-execution setting, secrets in files, persistence points, integrity drift, and optional SkillSpector/gitleaks/pip-audit. Returns a 0-100 score and the top three fixes. Read-only.
---

# Posture audit

1. Check the tools exist: `test -f /workspace/watchtower/app/watchtower/wt.py`. If missing, say so and offer /watchtower-setup. Never reinstall silently from an unpinned source.
2. Run `python3 /workspace/watchtower/app/watchtower/wt.py audit`. Output is compact JSON (under 4 KB): score, new findings, fixed findings, open counts by severity, top fixes, coverage notes.
3. Reply in at most 10 lines:
   - Score and grade, and the change since last run.
   - New since last run (severity, title, where).
   - The three fixes worth doing, each with the exact click path or command from `fix`.
   - Coverage gaps from `notes` in one line (for example, "routines not checked: no exports").
4. If the user wants to accept a risk, add `{"key": "<key>", "reason": "<their words>", "expires": "<date 90 days out>"}` to /workspace/watchtower/state/suppressions.json, with their yes.

## Never
- Fix anything yourself. Every fix is a recommendation; changing settings, deleting files, revoking connectors, or editing other Bots needs the user's explicit yes, one action at a time.
- Paste secrets. Evidence is already masked; keep it that way.
