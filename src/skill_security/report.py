"""JSON / Markdown reports."""

from __future__ import annotations

import json
from pathlib import Path

from skill_security.models import ScanReport, Severity


def write_json(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def render_markdown(report: ScanReport) -> str:
    status = "PASS" if report.ok else "FAIL"
    lines = [
        f"# Skill Security Scan — {status}",
        "",
        f"- tool: `dup-skill-security-scan` `{report.tool_version}`",
        f"- root: `{report.root}`",
        f"- skills: **{report.skill_count}**",
        f"- errors: **{len(report.errors)}**",
        f"- allowlist denied: **{len(report.allowlist_denied)}**",
        "",
    ]
    if report.allowlist_denied:
        lines.append("## Allowlist denied")
        lines.append("")
        for name in report.allowlist_denied:
            lines.append(f"- `{name}`")
        lines.append("")
    if report.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Sev | Skill | Code | Message |")
        lines.append("|-----|-------|------|---------|")
        for f in report.findings:
            msg = f.message.replace("|", "\\|")
            lines.append(
                f"| {f.severity.value} | `{f.skill}` | `{f.code}` | {msg} |"
            )
        lines.append("")
    else:
        lines.append("No heuristic findings.")
        lines.append("")
    if report.skill_hashes:
        lines.append("## SKILL.md sha256")
        lines.append("")
        for name, digest in sorted(report.skill_hashes.items()):
            lines.append(f"- `{name}`: `{digest}`")
        lines.append("")
    return "\n".join(lines)


def write_markdown(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report), encoding="utf-8")


def print_summary(report: ScanReport) -> None:
    status = "PASS" if report.ok else "FAIL"
    print(
        f"skill_security {status} n={report.skill_count} "
        f"errors={len(report.errors)} denied={len(report.allowlist_denied)}"
    )
    for f in report.findings:
        if f.severity is Severity.INFO:
            continue
        print(f" - [{f.severity.value}] {f.skill}: {f.code} — {f.message}")
    for name in report.allowlist_denied:
        print(f" - [deny] allowlist: {name}")
