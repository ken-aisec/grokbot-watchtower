# Changelog

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
