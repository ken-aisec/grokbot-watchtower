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
| the GitHub host in the link the owner gave | `vet` of a GitHub link | `git clone --depth 1` of that one repository, to vet its files |
| pypi.org, files.pythonhosted.org | `fix --upgrade` (after the owner's yes) | the newer versions of the outdated Python packages in the preview |
| registry.npmjs.org; crates.io, index.crates.io, static.crates.io | `fix --upgrade-projects`, only after the owner's own yes for it | npm's lockfile fix and `cargo update --precise` in the owner's own projects |
| semgrep.dev | `codescan`, only if semgrep is in Watchtower's checked scanner folder | the `p/owasp-top-ten` rules. Watchtower runs it with `--metrics=off` and `--disable-version-check`, so semgrep sends no usage metrics and doesn't ask semgrep.dev for a newer version. semgrep isn't installed by default, and a semgrep found elsewhere (on PATH) is never run |

Nothing else. No telemetry. Findings never leave the computer unless you send a report somewhere yourself.
