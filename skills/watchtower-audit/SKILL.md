---
name: watchtower-audit
description: Full security posture audit of this Grok Bot computer and roster - skills (Watchtower rules plus SkillSpector and husk, with corroboration), plugins, MCP configs, Auto Review rules, local execution, logged-in browser sessions, CLI credentials, secrets (gitleaks), vulnerable packages (pip-audit), persistence, integrity drift, canary tripwires, shell history, and the latest roll-call. Returns a 0-100 score and the top three fixes. Read-only.
---

# Posture audit

1. Check the tools exist: `test -f /workspace/watchtower/app/watchtower/wt.py`. If missing, say so and offer /watchtower-setup. Never reinstall silently from an unpinned source.
2. Run `python3 /workspace/watchtower/app/watchtower/wt.py audit`. Output is compact JSON (under 4 KB): score, new findings, fixed findings, open counts by severity, top fixes, coverage notes.
3. Reply in at most 10 lines:
   - Score and grade, and the change since last run.
   - New since last run (severity, title, where).
   - The three fixes worth doing, each with the exact click path or command from `fix`.
   - Coverage gaps from `notes` in one line (for example, "SkillSpector not installed" or "no roll-call in 35 days").
   - For any finding, `wt.py show <RULE>` prints the evidence with surrounding lines (never for secrets).
4. If the user wants to accept a risk, add `{"key": "<key>", "reason": "<their words>", "expires": "<date 90 days out>"}` to /workspace/watchtower/state/suppressions.json, with their yes.

## Never
- Fix anything yourself. Every fix is a recommendation; changing settings, deleting files, revoking connectors, or editing other Bots needs the user's explicit yes, one action at a time.
- Paste secrets. Evidence is already masked; keep it that way.
