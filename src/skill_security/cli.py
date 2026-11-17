"""CLI: scan / check-install / hashes."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from skill_security import __version__
from skill_security.allowlist import apply_allowlist, load_allowlist
from skill_security.models import Finding, Severity
from skill_security.report import print_summary, write_json, write_markdown
from skill_security.scanner import list_skill_dirs, resolve_skills_root, scan_pack


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dup-skill-security-scan",
        description=(
            "Fail-closed security scanner + allowlist gate for Agent Skills packs."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Heuristic scan of a skills pack")
    scan.add_argument("root", type=Path, help="Pack root (contains skills/)")
    scan.add_argument("--allowlist", type=Path, default=None)
    scan.add_argument(
        "--source",
        default="Gruver87/dup-agent-skills",
        help="Claimed source for allowlist matching",
    )
    scan.add_argument("--skip-allowlist", action="store_true")
    scan.add_argument("--report-dir", type=Path, default=None)
    scan.add_argument("--no-report", action="store_true")

    inst = sub.add_parser(
        "check-install",
        help="Refuse install unless allowlisted and scan clean",
    )
    inst.add_argument("root", type=Path)
    inst.add_argument("--allowlist", type=Path, default=None)
    inst.add_argument("--source", default="Gruver87/dup-agent-skills")
    inst.add_argument(
        "--skills",
        nargs="*",
        default=None,
        help="Subset of skill folder names (default: all)",
    )

    hashes = sub.add_parser("hashes", help="Print SKILL.md sha256 map as JSON")
    hashes.add_argument("root", type=Path)
    return p


def _attach_allowlist(
    report,
    *,
    allowlist_path: Path | None,
    source: str,
    skill_names: list[str] | None,
) -> None:
    allowlist = load_allowlist(allowlist_path)
    skills_root = resolve_skills_root(Path(report.root))
    names = skill_names or [d.name for d in list_skill_dirs(skills_root)]
    denied = apply_allowlist(
        names,
        allowlist,
        source=source,
        hashes=report.skill_hashes,
    )
    report.allowlist_denied = [name for name, _ in denied]
    for name, reason in denied:
        report.findings.append(
            Finding(
                skill=name,
                code="allowlist_deny",
                message=reason,
                severity=Severity.ERROR,
            )
        )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "hashes":
        report = scan_pack(args.root)
        print(json.dumps(report.skill_hashes, indent=2, ensure_ascii=False))
        return 0 if report.skill_hashes else 1

    if args.cmd == "scan":
        report = scan_pack(args.root)
        if not args.skip_allowlist:
            _attach_allowlist(
                report,
                allowlist_path=args.allowlist,
                source=args.source,
                skill_names=None,
            )
        print_summary(report)
        if not args.no_report:
            out = args.report_dir or (Path("reports") / "skill-security")
            write_json(report, out / "report.json")
            write_markdown(report, out / "report.md")
            print(f"report: {out / 'report.json'}")
        return 0 if report.ok else 1

    if args.cmd == "check-install":
        report = scan_pack(args.root)
        _attach_allowlist(
            report,
            allowlist_path=args.allowlist,
            source=args.source,
            skill_names=list(args.skills) if args.skills else None,
        )
        print_summary(report)
        if report.ok:
            print("check-install ALLOW")
            return 0
        print("check-install REFUSE", file=sys.stderr)
        return 1

    print("unknown command", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
