---
name: watchtower-codescan
description: Review code your Bots wrote (a web app, an API, scripts in /workspace) for the OWASP Top 10 (2021) - injection, broken access control, crypto failures, misconfiguration, unsafe deserialization, SSRF and hard-coded secrets. Uses semgrep too if it's installed.
---

# Code review for OWASP Top 10

1. Ask which folder, or use the one the user named. Run `python3 /workspace/watchtower/app/watchtower/wt.py codescan <folder>`.
2. Reply with counts by severity, then each critical and high finding: file and line, the OWASP category, the flagged code, and the fix in one sentence. Group repeats.
3. Offer to fix them, one file at a time, only with the user's yes, and only in that folder. Re-run codescan after.

Pattern matching finds likely problems, not proven ones. Say so once, and confirm before calling anything a vulnerability.
