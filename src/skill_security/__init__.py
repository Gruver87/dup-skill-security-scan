"""DUP Skill Security Scan — allowlist + heuristic gate for Agent Skills."""

from __future__ import annotations

__version__ = "0.1.0"

from skill_security.models import Finding, ScanReport, Severity
from skill_security.scanner import scan_pack, scan_skill_dir

__all__ = [
    "__version__",
    "Finding",
    "ScanReport",
    "Severity",
    "scan_pack",
    "scan_skill_dir",
]
