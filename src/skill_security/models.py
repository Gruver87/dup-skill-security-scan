"""Finding / report types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    ERROR = "error"
    WARN = "warn"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    skill: str
    code: str
    message: str
    severity: Severity = Severity.ERROR
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanReport:
    root: str
    skill_count: int
    findings: list[Finding] = field(default_factory=list)
    allowlist_denied: list[str] = field(default_factory=list)
    skill_hashes: dict[str, str] = field(default_factory=dict)
    tool_version: str = "0.1.0"

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.ERROR]

    @property
    def ok(self) -> bool:
        return not self.errors and not self.allowlist_denied

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_version": self.tool_version,
            "root": self.root,
            "skill_count": self.skill_count,
            "ok": self.ok,
            "error_count": len(self.errors),
            "warn_count": len([f for f in self.findings if f.severity is Severity.WARN]),
            "allowlist_denied": list(self.allowlist_denied),
            "skill_hashes": dict(self.skill_hashes),
            "findings": [f.to_dict() for f in self.findings],
        }
