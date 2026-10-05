---
name: watchtower-report
description: Write the weekly Watchtower security report and dashboard from the latest audit, and post a short summary. Use after /watchtower-audit or in the weekly routine.
---

# Weekly report

1. Run `python3 /workspace/watchtower/app/watchtower/wt.py report`. It writes `/workspace/watchtower/reports/<year>-W<week>.md` and `/workspace/watchtower/reports/dashboard.html` (self-contained, light and dark) and prints the report's first lines.
2. Post the summary in this conversation in at most 8 lines: score and trend, counts by severity, the top three fixes, and one line on accepted risks that expire within 14 days.
3. Attach `dashboard.html` to the conversation so the user can open it.
4. Sending the report anywhere else (Slack, email) uses the user's connector and needs their approval the first time.

If the audit is older than 8 days, run /watchtower-audit first. If it fails, report the failure; never resend last week's report as new.
