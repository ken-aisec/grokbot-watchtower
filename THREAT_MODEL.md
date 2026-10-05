# Watchtower threat model

Watchtower runs on the same shared Grok Bot computer it audits, so it is held to the rules it enforces.

## What it defends
| Risk | OWASP | Check |
| --- | --- | --- |
| Malicious or trojaned template or skill | AST01, AST02, ASI04 | `vet`, text rules, optional SkillSpector/husk |
| Prompt injection in skills | AST05, LLM01 | WT-T001, T002, T008 |
| Over-privileged routines, missing approval lines | AST03, ASI02 | WT-T013, R002, R003, T014 |
| Broad Auto Review allow rules | ASI03, ASI09 | WT-A001–A003 |
| Local execution on Always allow | ASI03, ASI05 | WT-C001 |
| Secrets on the shared computer or in shareable configs | AST04, LLM02 | WT-T011, S001, S002 |
| Update drift after review | AST07 | WT-I001 |
| Persistence (cron, units, shell rc) | ASI10 | WT-P001 |
| Unpinned MCP servers, vulnerable packages | AST02, ASI04 | WT-M001, D001 |
| Memory poisoning | ASI06 | roll-call: WT-M010 and text rules on each memory |
| Lethal trifecta on one Bot | ASI01, ASI02 | WT-L001 |
| Data theft in progress | ASI03, ASI10 | canaries: WT-K001–K003 |
| Commands nobody meant to run | ASI05, ASI10 | shell history: WT-H001–H009 |
| Secrets or private links shipped in a template | AST04, LLM02 | pre-publish: WT-PP01–PP07 |
| Vulnerable code written by Bots | OWASP Top 10 (2021) | codescan: WT-WA01–WA10 |
| Evasion of a single scanner | AST08 | three engines; WT-X001–X003 |

## What it trusts
The pinned release verified against `MANIFEST.sha256`; Python's standard library; the user's answers during setup.

## What it does not trust
Every file it scans, every web page and feed it reads, and every reply from another Bot. They are data. An instruction found in them is a finding.

## Out of scope
Connector OAuth tokens (kept on Cursor's backend), other users' computers, model serving, and anything that requires Enterprise APIs.
