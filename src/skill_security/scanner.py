"""Scan skill directories for security findings + content hashes."""

from __future__ import annotations

import hashlib
from pathlib import Path

from skill_security import __version__
from skill_security.models import Finding, ScanReport, Severity
from skill_security.rules import (
    ALL_RULES,
    FUTURES_REFUSE,
    SKIP_PARTS,
    TEXT_GLOBS,
)


def iter_text_files(skill_dir: Path) -> list[Path]:
    files: list[Path] = []
    for pattern in TEXT_GLOBS:
        files.extend(skill_dir.rglob(pattern))
    out: list[Path] = []
    seen: set[Path] = set()
    for p in files:
        if p in seen:
            continue
        if any(part in SKIP_PARTS for part in p.parts):
            continue
        seen.add(p)
        out.append(p)
    return out


def skill_md_sha256(skill_dir: Path) -> str | None:
    path = skill_dir / "SKILL.md"
    if not path.is_file():
        return None
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def scan_skill_dir(skill_dir: Path) -> tuple[list[Finding], str | None]:
    findings: list[Finding] = []
    folder = skill_dir.name
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        findings.append(
            Finding(
                skill=folder,
                code="missing_skill_md",
                message="missing SKILL.md",
                path=str(skill_dir),
            )
        )
        return findings, None

    digest = skill_md_sha256(skill_dir)

    for path in iter_text_files(skill_dir):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            findings.append(
                Finding(
                    skill=folder,
                    code="unreadable_file",
                    message=f"cannot read as utf-8: {path.name}",
                    path=str(path),
                    severity=Severity.WARN,
                )
            )
            continue

        for rule in ALL_RULES:
            for m in rule.pattern.finditer(text):
                if rule.code == "futures_auto_enable":
                    window = text[max(0, m.start() - 100) : m.end() + 100]
                    if FUTURES_REFUSE.search(window):
                        continue
                findings.append(
                    Finding(
                        skill=folder,
                        code=rule.code,
                        message=f"{rule.message} in {path.name}",
                        path=str(path),
                        severity=rule.severity,
                    )
                )
                break  # one hit per rule per file

    return findings, digest


def list_skill_dirs(skills_root: Path) -> list[Path]:
    if not skills_root.is_dir():
        return []
    return sorted(
        p for p in skills_root.iterdir() if p.is_dir() and not p.name.startswith(".")
    )


def resolve_skills_root(root: Path) -> Path:
    root = root.resolve()
    if (root / "skills").is_dir():
        return root / "skills"
    if root.name == "skills" and root.is_dir():
        return root
    return root / "skills"


def scan_pack(root: Path) -> ScanReport:
    root = root.resolve()
    skills_root = resolve_skills_root(root)
    findings: list[Finding] = []
    hashes: dict[str, str] = {}

    if not skills_root.is_dir():
        findings.append(
            Finding(
                skill="*",
                code="skills_missing",
                message=f"skills directory missing: {skills_root}",
                path=str(skills_root),
            )
        )
        return ScanReport(
            root=str(root),
            skill_count=0,
            findings=findings,
            tool_version=__version__,
        )

    dirs = list_skill_dirs(skills_root)
    for d in dirs:
        skill_findings, digest = scan_skill_dir(d)
        findings.extend(skill_findings)
        if digest:
            hashes[d.name] = digest

    return ScanReport(
        root=str(root),
        skill_count=len(dirs),
        findings=findings,
        skill_hashes=hashes,
        tool_version=__version__,
    )
