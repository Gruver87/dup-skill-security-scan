# Architecture — dup-skill-security-scan

**Org:** DUP Labs · **Role:** install-time security + allowlist for Agent Skills

## Why

Marketplace skills can ship secrets, download-exec, or futures-auto enable.
This tool is a **fail-closed** gate before `install_user_skills` / Cursor plugin use.

Complements [`dup-skills-eval`](https://github.com/Gruver87/dup-skills-eval)
(static/honesty). This pack focuses on **threat heuristics + allowlist**.

## Gates

| Gate | Behavior |
|------|----------|
| Heuristic scan | secrets, download-exec, obfuscation, exfil, TLS off, futures enable |
| Allowlist | skill name (+ optional sha256) from trusted source only |
| check-install | ALLOW only if scan clean **and** all skills allowlisted |

## CLI

```text
dup-skill-security-scan scan <pack>
dup-skill-security-scan check-install <pack>
dup-skill-security-scan hashes <pack>
```
