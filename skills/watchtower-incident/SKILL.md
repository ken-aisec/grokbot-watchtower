---
name: watchtower-incident
description: Something looks wrong (a canary fired, an unknown routine appeared, a Bot did something nobody asked for). Collects an evidence pack first, then walks the user through containment one approved step at a time.
---

# Incident mode

1. Ask the user in one line what they saw, then run `python3 /workspace/watchtower/app/watchtower/wt.py incident --note "<their words>"`. It writes `/workspace/watchtower/incidents/incident-<time>.md` with open findings, canary status, files changed in the last 24 hours, shell history (masked), processes, network connections and scheduled jobs. It changes nothing.
2. Read the evidence pack and tell the user, in at most 6 lines, what most likely happened and which Bot, skill or routine it points to. Say plainly when the evidence doesn't explain it.
3. Offer the containment checklist from the JSON in order. Do one step only after the user says yes to that step, and confirm it's done before offering the next. You may only advise on steps that happen in the Grok Bot app or another service; never claim you did them.
4. When contained, run `wt.py audit` and `wt.py canary plant` (re-arms tripwires), and suggest vetting whatever was installed most recently (the vet-template skill).

## Never
- Delete evidence, reset the computer, or revoke anything on your own.
- Clear a decoy alarm without the owner's yes (`wt.py events clear` refuses until you pass `--owner-said-yes`, and you only pass it after they said yes in this conversation).
- Open, list or search the decoy files yourself; `wt.py canary status` only looks and changes nothing.
