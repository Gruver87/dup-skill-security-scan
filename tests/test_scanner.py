from __future__ import annotations

from pathlib import Path

from skill_security.scanner import scan_pack, scan_skill_dir

FIXTURES = Path(__file__).parent / "fixtures"


def test_good_skill_clean() -> None:
    findings, digest = scan_skill_dir(
        FIXTURES / "good_pack" / "skills" / "no-futures-auto"
    )
    assert digest
    errors = [f for f in findings if f.severity.value == "error"]
    assert errors == []


def test_bad_skill_flags() -> None:
    findings, _ = scan_skill_dir(FIXTURES / "bad_pack" / "skills" / "evil-skill")
    codes = {f.code for f in findings}
    assert "download_exec" in codes
    assert "futures_auto_enable" in codes
    assert "sk_live_token" in codes or "generic_api_key_assign" in codes


def test_scan_pack_counts() -> None:
    report = scan_pack(FIXTURES / "good_pack")
    assert report.skill_count == 1
    assert report.ok
