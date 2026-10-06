Every day at 6:00 AM in my time zone, run:
python3 /workspace/watchtower/app/watchtower/wt.py daily

It checks skill changes, new persistence, canary tripwires and new shell history, and runs the scanning engines on anything new or changed.
If it prints NO_CHANGES, send nothing and stop. If it prints BUSY, another Watchtower run is going: send nothing and stop.
If it prints SCANNERS_MISSING, a restart removed the scanners I approved at setup: run the one command it gives, then run the daily check once more. That reinstall is the only change this routine may make.
If it prints JSON, post at most 6 lines: each new finding (severity, title, where) and the fix for the most severe one. If a canary fired, say so first and offer /watchtower-incident.
If the script is missing or errors, report the failure in one line; never reuse old findings.
Read-only: do not fix, delete, install, or change anything. Ask me first before any action.
