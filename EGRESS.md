# Every host Watchtower contacts

| Host | When | Why |
| --- | --- | --- |
| github.com, raw.githubusercontent.com | setup, updates | the pinned release and its manifest |
| github.com/NVIDIA, github.com/gitleaks, github.com/trufflesecurity, github.com/google, pypi.org, files.pythonhosted.org | `install.sh --scanners` | pinned scanners |
| api.github.com | weekly brief | latest release of Watchtower and each scanner |
| www.cisa.gov | weekly brief | Known Exploited Vulnerabilities catalog |
| docs.x.ai, owasp.org | weekly brief | detect changes to Grok Bot security docs and OWASP AST10 |
| the feeds in `rules/feeds.json` | weekly brief | research and news (Trail of Bits, Simon Willison, Embrace The Red, Snyk Labs, Invariant Labs, CSA Labs, OWASP GenAI, Socket, GitHub Security Lab, The Hacker News) |
| pypi.org / osv.dev | weekly audit, via pip-audit and OSV-Scanner | known vulnerabilities in installed packages and project dependencies |
| each key's own provider (AWS, GitHub, Slack, Square, and so on) | weekly audit, via TruffleHog, only for keys already found in files | asks the provider whether the key still works; the key goes only to its own provider |
| x.ai | vetting a template link | read the public template page |

Nothing else. No telemetry. Findings never leave the computer unless you send a report somewhere yourself.
