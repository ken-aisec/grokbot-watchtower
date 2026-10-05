Every day at 6:00 AM in my time zone, run:
python3 /workspace/watchtower/app/watchtower/wt.py daily

If it prints NO_CHANGES, send nothing and stop.
If it prints JSON, post at most 6 lines: each new finding (severity, title, where) and the fix for the most severe one. Mention fixed findings in one line.
If the script is missing or errors, report the failure in one line; never reuse old findings.
Read-only: do not fix, delete, install, or change anything. Ask me first before any action.
