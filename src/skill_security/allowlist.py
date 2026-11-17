"""Allowlist gate — fail-closed install policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ALLOWLIST = PACKAGE_ROOT / "configs" / "allowlist.json"


@dataclass(frozen=True)
class AllowlistEntry:
    name: str
    source: str
    sha256: str | None = None


@dataclass
class Allowlist:
    trusted_sources: list[str]
    entries: dict[str, AllowlistEntry]
    policy: str = "fail-closed"

    def check_skill(
        self,
        name: str,
        *,
        source: str | None = None,
        sha256: str | None = None,
    ) -> tuple[bool, str]:
        entry = self.entries.get(name)
        if entry is None:
            return False, f"skill {name!r} not on allowlist"
        if source is not None and source != entry.source:
            # Soft alias: local:dup-agent-skills ↔ listed GitHub source if trusted
            aliases = {
                "local:dup-agent-skills": "Gruver87/dup-agent-skills",
                "Gruver87/dup-agent-skills": "local:dup-agent-skills",
            }
            if aliases.get(source) != entry.source:
                return False, (
                    f"skill {name!r} source {source!r} != allowlist {entry.source!r}"
                )
        if entry.sha256:
            if not sha256:
                return False, f"skill {name!r} requires sha256 pin but none provided"
            if entry.sha256.lower() != sha256.lower():
                return False, f"skill {name!r} sha256 mismatch"
        return True, "allowlisted"


def load_allowlist(path: Path | None = None) -> Allowlist:
    cfg_path = path or DEFAULT_ALLOWLIST
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("allowlist must be a JSON object")
    entries: dict[str, AllowlistEntry] = {}
    for raw in data.get("skills") or []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()
        source = str(raw.get("source") or "").strip()
        if not name or not source:
            continue
        sha = raw.get("sha256")
        entries[name] = AllowlistEntry(
            name=name,
            source=source,
            sha256=str(sha).strip() if sha else None,
        )
    return Allowlist(
        trusted_sources=[str(s) for s in (data.get("trusted_sources") or [])],
        entries=entries,
        policy=str(data.get("policy") or "fail-closed"),
    )


def apply_allowlist(
    skill_names: list[str],
    allowlist: Allowlist,
    *,
    source: str | None = None,
    hashes: dict[str, str] | None = None,
) -> list[tuple[str, str]]:
    """Return list of (name, reason) denied."""
    denied: list[tuple[str, str]] = []
    hashes = hashes or {}
    for name in skill_names:
        ok, reason = allowlist.check_skill(
            name, source=source, sha256=hashes.get(name)
        )
        if not ok:
            denied.append((name, reason))
    return denied


def allowlist_to_dict(allowlist: Allowlist) -> dict[str, Any]:
    return {
        "policy": allowlist.policy,
        "trusted_sources": list(allowlist.trusted_sources),
        "skills": [
            {
                "name": e.name,
                "source": e.source,
                **({"sha256": e.sha256} if e.sha256 else {}),
            }
            for e in sorted(allowlist.entries.values(), key=lambda x: x.name)
        ],
    }
