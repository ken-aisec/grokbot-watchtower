# Every host Watchtower contacts

| Host | When | Why |
| --- | --- | --- |
| github.com, raw.githubusercontent.com | setup and updates | the pinned release and its manifest |
| github.com/gitleaks, github.com/NVIDIA | `--scanners` only | optional scanners |
| pypi.org, files.pythonhosted.org | `--scanners` only | optional scanners' packages |
| x.ai | `/vet-template` with a link | read the public template preview |
| api.osv.dev, pypi.org | when SkillSpector or pip-audit run | known-vulnerability lookups |

Nothing else. Watchtower sends no telemetry and never uploads findings.
