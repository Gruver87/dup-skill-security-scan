# DUP Skill Security Scan

[![ci](https://github.com/Gruver87/dup-skill-security-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Gruver87/dup-skill-security-scan/actions/workflows/ci.yml)

**Org:** [DUP Labs](https://github.com/Gruver87) · **Author:** Uladzimir Dabranski  
**Version:** `0.1.0` · Fail-closed **scanner + allowlist** for Agent Skills installs

Before installing skills into Cursor / `.agents`, run this gate.

| Related | Role |
|---------|------|
| [`dup-agent-skills`](https://github.com/Gruver87/dup-agent-skills) | Trusted pack (allowlisted) |
| [`dup-skills-eval`](https://github.com/Gruver87/dup-skills-eval) | Static + honesty eval |
| [`dup-evidence-graph`](https://github.com/Gruver87/dup-evidence-graph) | Evidence claim map |

## Install

```powershell
cd C:\Users\vovun\Desktop\dup-skill-security-scan
python -m pip install -e ".[dev]"
.\scripts\test_all.ps1
.\scripts\scan_agent_skills.ps1
```

## CLI

```powershell
python -m skill_security scan ..\dup-agent-skills
python -m skill_security check-install ..\dup-agent-skills
python -m skill_security hashes ..\dup-agent-skills
```

`check-install` exit `0` = ALLOW · `1` = REFUSE.

## Allowlist

Edit [`configs/allowlist.json`](configs/allowlist.json). Optional `sha256` pins per skill
(from `hashes` command). Unknown skills are denied.

## License

MIT — [`LICENSE`](LICENSE).
