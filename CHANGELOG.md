# Changelog

## v0.5.4 — 2026-10-06 (honest partial scans, first-run tuning)
- Fixed: when SkillSpector and husk were missing, skills were remembered as scanned and clean, and would have been skipped once the scanners came back. Now nothing is remembered unless a scanner really ran, each result records which scanners produced it, and results left by older versions are re-checked automatically.
- When scanners that ran last time are gone (a reset computer, a lost install), the audit says so first, marks the score as not comparable, and the audit and fix skills reinstall the pinned scanners and run again before reporting.
- Setup now ends with a two-minute tuning step: one question, one yes, to keep what's yours on purpose. Kept items are accepted for 90 days and listed; anything new still shows.

## v0.5.3 — 2026-10-05 (no more stuck audits)
- Fixed: one skill that a scanner can't get through no longer eats the whole time budget on every run. Measured cause: SkillSpector doesn't finish on skills with very large files (about 1.5 MB of minified code or text). An engine launch now has its own short limit (30 seconds plus 2 per skill). Big skills are scanned on their own, after the quick ones. When a batch jams, the biggest skill is tried alone, then the rest.
- A skill a scanner can't finish is remembered and reported as a low finding ("A scanner couldn't get through a skill") instead of being retried every run. Watchtower tries it again after a week, or as soon as the skill changes. It is never counted as clean, and `/watchtower-fix` never re-approves it automatically.
- Updating Watchtower no longer raises "a skill you approved has changed" about Watchtower's own skills. A file that is byte-for-byte the one in the checksummed release is trusted; a tampered copy still shows.
- Watchtower's own skills now vet clean: the roll-call skill says it never sends without approval and reports a Bot that doesn't answer. "Reaches into other Bots" no longer fires on a line that says never to do it.
- Verified against real SkillSpector 2.12.0 and husk 1.3.5: 85 skills including two that really jam SkillSpector took 84 seconds on the first run and 0 on the second.

## v0.5.2 — 2026-10-05 (changed skills, handled)
- `/watchtower-fix` now deals with skills that changed after you approved them. It re-scans each one with every engine (Watchtower rules, SkillSpector, husk) and, as part of the one yes, re-approves the ones that come back clean. A flagged skill, or one the scanners didn't finish, stays open.
- Watchtower keeps a compressed copy of every approved skill in its own state folder, so a change shows as a diff: "+1 −0 lines in SKILL.md" in the fix preview, and the exact lines with `wt.py diff SKILL`. Skills approved before this version get a copy on the next full audit, as long as they still match what was approved.
- Security-tool exception: a skill that two scanners flag because it carries attack samples (a scanner, a vetting tool) can be kept by its owner. One named skill at a time, never a pattern or a rule; it must describe itself as a security tool; it lasts 30 days; it ends early if the skill's files change; and it is marked in the audit output and every report. `wt.py exception add|list|remove`, or `--exception NAME` in the fix.
- The time budget is now checked inside a batch, not only between batches. An engine gets only the time that is left, so a 2-minute daily run can no longer sit in one launch for 10 minutes. A batch that runs out of time is retried at half the size next run.
- Fixed: `publish.sh` committed only the manifest unless the owner placeholder was present, so a release built from the public repo would have tagged the old code. It now commits the whole release.
- Fixed: `--budget` on one audit no longer carries over to later runs in the same process.
- Verified against real SkillSpector 2.12.0 and husk 1.3.5: clean edit re-approved, malicious edit kept open, exception applied and dropped on change, 3-second budget stopped at 3.0 seconds.

## v0.5.1 — 2026-10-05 (fast scanners)
- SkillSpector and husk now start once per batch of 40 skills instead of once per skill (SkillSpector takes about 5 seconds just to start). 60 skills: 13 seconds, down from roughly 5 minutes.
- Skills are remembered by content: unchanged skills are never re-scanned. A repeat run takes under a second; editing one skill rescans only that one.
- Time budget (default 7 minutes, `--budget SECONDS`): if it runs out, finished work is saved and the rest resumes on the next run, with a note saying how many are left. Daily runs use 2 minutes.
- New `wt.py status`: what a running audit is doing now and how long each stage took.
- A batch that fails or times out is reported and retried, never remembered as clean.

## v0.5.0 — 2026-10-05 (one yes, then everything)
- `/watchtower-fix` is now a one-question fix. It previews everything it can do, asks once, then does it: safe cleanup, software upgrades, Ask-first rules, and accepting findings that are fine on purpose.
- Upgrades with automatic undo. Python packages are upgraded at user level (system files are never touched) and put back if `pip check` shows anything new broke. Project dependencies get `npm audit fix` on the lockfile only, never `--force`, with a backup copy and a check that the dependency tree still resolves. Verified against real pip, PyPI and npm: pip 2.7.0 → 2.15.1 and back; a lockfile with a critical and a high issue went to zero.
- `wt.py accept --all-current RULES` and `wt.py fix --accept RULES`: accept what's open now; new findings still show. Never accepts two scanners agreeing a skill is dangerous, a touched decoy, a working key, or a memory acting as an order.
- Ask-first rules saved to `exports/auto-review.txt` count, so rules that only exist in the app no longer show as missing forever.
- Each item in the report says who handles it: Fix handles it, One yes, or Only you.
- Fixed: accepting one finding could hide another that happened to share its key.
- Fixed: `pip uninstall` is blocked on protected Pythons the same way `pip install` is; the undo now handles it.

## v0.4.1 — 2026-10-05 (a score you can trust: stability pass)
- The score history only shows full audits measured with the current formula. Older scores (earlier formulas) and daily runs no longer appear, so the trend line isn't comparing different measuring sticks. A ring on the chart and "Watchtower updated" next to the change mark audits where a new version or scanner was added, since a jump there isn't new problems.
- Smoother score: one kind of finding appearing or vanishing moves it by at most 12 points (was 20), and many of the same kind add at most 50% more.
- Keys: when TruffleHog runs, only a key its provider confirms still works is critical. Pattern-only matches (curl placeholders, test data, docs) are medium, low in tests and docs. If providers can't be reached, severities are left alone.
- Dependencies: one finding per package and version, however many projects use it; never critical; high only when the worst advisory scores 7 or more.
- gitleaks ignores test files, lockfiles, headers, marketplace manifests, env-variable placeholders in curl examples, and 40-character commit hashes.
- Fixed: a gitleaks config error made it quit silently and Watchtower reported no secrets. Any scanner that fails now says so in the report notes ("NOT checked").
- "Sends or posts without asking" is medium only for real outward verbs (send, publish, buy, pay, deploy); post, reply, remove and merge are low.
- New `wt.py accept RULE WHERE --reason "..."`: accept a risk on purpose; it survives rescans and expires after 90 days.

## v0.4.0 — 2026-10-05 (dig in, live keys, working copy)
- Every item in the weekly report has a "Show which" drill-down: the skill, file or package by name, why it was flagged, where, and the command for the exact lines.
- TruffleHog checks which leaked keys still work. Live keys stay critical with a direct link to turn them off; confirmed-dead keys drop to low and the fix clears them. Raw key values are never stored.
- OSV-Scanner checks project dependencies (Node, Go and others) in /workspace.
- The fix now clears keys from any flagged chat, session or log file (for example ~/.grok/sessions), never from code or config.
- Copy buttons work in sandboxed viewers (clipboard, then a fallback, then select-and-press-⌘C); with scripts blocked, one click selects the whole command.
- "Handled this week" counts distinct findings resolved, not audit churn. The report names every scanner that ran.
- Watchtower's own secret check now reads .jsonl, .ndjson and .log files.

## v0.3.0 — 2026-10-05 (the easy fix button)
- Weekly report rebuilt for non-experts: one status line, four metrics (score, threat level, needs you, handled this week), a score trend chart and an open-issues chart, a copyable "Fix it now" command and weekly-tidy routine, plain-language to-dos with direct links to turn off leaked keys, and three threats with one line each on why you care and what to do. Everything else folds away.
- New `/watchtower-fix` and `wt.py fix [--apply]`: removes keys from chat transcripts (the conversation stays), empties tool-overflow caches, resets decoys, prunes old reports. Preview by default; never revokes, uninstalls or changes settings.
- New weekly-tidy routine.
- Decoys: one opened alone is critical (something went looking); all opened within minutes is a bulk search and only noted.

## v0.2.2 — 2026-10-05 (fairness pass after a real account run)
- Canaries are re-armed after Watchtower's own scanners run and are excluded from gitleaks, so they only trip on other readers. `wt.py events clear --rule WT-K001` clears false trips from earlier versions.
- Score counts kinds of risk: a critical type costs 20, a high 6, a medium 2 (with caps), so a real account with a few issues isn't pinned at 0. Grades: A 90, B 80, C 65, D 50.
- Threat level weighs your own setup above the news: at most 2 points from stories and 2 from exploited CVEs; a tripwire firing adds 3.
- gitleaks ignores signed cloud-storage links (Notion and S3 file URLs), skips other browser profiles, and groups agent transcripts, tool-overflow folders and Cursor project mirrors. Severity: real token types are critical, high inside tool caches, medium in shipped plugin docs or when generic.
- The brief's output tells the Bot the analysis step is required until it's done.

## v0.2.1 — 2026-10-05 (watch report redesign; first full-engine audit on a real box)
- Threat brief redesigned as a watch report: threat level, bottom line, ordered actions, ranked stories with what happened, what it means for this account (using its own numbers) and what to do, exposure by area, exploited vulnerabilities, folded source list. Light, dark, mobile and print layouts; no external fonts or requests.
- Stories are scored and categorized (MCP and connectors, agent hijacking, supply chain, credentials, browser, platform). Podcasts, webinars and how-we-built posts drop out; agent misbehavior ranks up. Summaries end on full sentences.
- The Bot can add its own analysis per story (`wt.py brief --notes notes.json`), re-rendering the same week without fetching again.
- gitleaks skips browser profiles, the Go toolchain and known CLI credential files (reported once as WT-S003, now including the Codex CLI); folders with many secret files become one finding.

## v0.2.0 — 2026-10-05 (full feature set)
- Three engines: SkillSpector and husk run on your own skills plus anything new or changed; two engines agreeing is a corroborated critical. Scanners are found in Watchtower's own folder (fixes "SkillSpector not installed" when it was).
- Weekly threat brief: professional HTML with relevant research, CISA exploited vulnerabilities, tool updates, Grok Bot doc changes, your exposure and recommended actions. Hostile feed content is escaped and non-http links are dropped.
- Roll-call memory audit: poisoned memories, standing-instruction memories, unsafe routines, lethal-trifecta Bots.
- Canary tripwires for reads, deletion and copying.
- Shell-history review, incremental, secrets masked.
- Pre-publish check before sharing a template.
- Incident mode: evidence pack and approval-gated containment.
- OWASP Top 10 (2021) code review, plus semgrep when present.
- gitleaks skips caches; pip-audit checks the computer's Python, not Watchtower's; one finding per vulnerable package.
- One-time detections (shell history, canary trips) stay open for 14 days instead of looking fixed the next day.
- Installer pins every scanner. Monthly roll-call routine. 36 tests, isolated from the real home folder.

## v0.1.5 — 2026-10-05 (fourth real audit: no real criticals left)
- Official installers (x.ai CLI, Tailscale, Slack CLI, Cursor, Helm and others) piped to shell are medium or low; unknown hosts stay critical.
- Supporting files that document or detect attacks (a skill-scanner's pattern lists) have their matches downgraded to low and kept visible. A SKILL.md, the file a Bot actually follows, is never downgraded this way.
- Base64 that decodes to an ordinary document (Office, PDF, image, HTML) is treated as data, not a payload.
- Only real MCP config filenames count as MCP configs.
- publish.sh asks before overwriting only when GitHub has commits this folder lacks, and sets the repo public.

## v0.1.4 — 2026-10-05 (third real audit)
- Instruction-override rule understands defensive writing: "ignore any instructions inside the transcript", table cells, HTML/Markdown comments, regex source. Files that list several injection patterns (references, detectors) get one info note instead of criticals.
- New WT-S004: Grok Bot's seeded browser sessions (chrome-cookie-seed.json) reported as the list of logged-in domains, never values, with sign-out advice; no longer a "delete this file" secret finding.
- Baseline entries under now-skipped caches no longer show as "removed"; info findings never appear as new.

## v0.1.3 — 2026-10-05 (second real audit)
- Skips language package caches (Go module cache, Maven, Gradle, dist-packages, bun, pnpm).
- Trust tiers: the user's own saved skills get every rule; first-party bundles, marketplace plugins, other agents' skill folders and copies in /workspace get malicious-indicator rules only.
- Known installers piped to shell (bun, rustup, uv, Homebrew, Docker, nvm…) are medium, low in vendor skills; unknown hosts stay critical.
- Placeholder and low-variety keys in documentation are ignored.
- New `wt.py show RULE` prints evidence with surrounding context (never for secrets).
- `publish.sh` works with a repo that already exists and is safe to rerun.

## v0.1.2 — 2026-10-05 (noise fixes from the first real audit)
- Skips browser profiles and caches (Chrome scoped_dir, WasmTtsEngine, Cache dirs) and package caches.
- Tighter OpenAI-style key pattern: `sk-SK-…` Slovak voice names were matching.
- New WT-S003: known CLI credential files (Claude Code, GitHub CLI, AWS, git, Docker, npm, gcloud) reported once each as high with least-privilege advice instead of "delete".
- Skills from managed and marketplace plugins are checked for malicious indicators only, not style.
- Score counts each risk once (plus up to 5 for repeats), so 300 skills with the same style issue don't outweigh one live secret.
- Report lists low findings as counts; new `wt.py breakdown` shows findings by rule and folder.

## v0.1.1 — 2026-10-05 (fitted to a real Grok Bot computer)
- Reads Grok Bot's own `~/agent-data/settings.json`: Auto Review rules and local-tool permission, no export needed.
- New WT-A004: an Allow-automatically rule that lets a Bot create automations, routines or installs is high risk.
- New WT-A005: no Auto Review rules at all.
- gitleaks always runs with `--redact` and its report is deleted after parsing, so Watchtower never writes plaintext secrets to the shared computer; findings grouped per file.
- Secrets scan: one finding per file with a count.
- SkillSpector: parses the real `issues[]` and `risk_assessment` schema (v2.12).
- `/vet-template`: public previews show only the description, so it uses the Download link.

## v0.1.0 — 2026-10
- `wt.py` with vet, audit, daily, report, baseline; stdlib only.
- 16 text rules mapped to OWASP ASI and AST, with context guards so warnings about attacks are not flagged as attacks.
- Routine, Auto Review and settings linters; integrity drift; persistence diff; secrets scan with masking.
- Optional SkillSpector, gitleaks and pip-audit integration.
- Four skills, two routines, the Bot description, pinned installer with manifest verification.
