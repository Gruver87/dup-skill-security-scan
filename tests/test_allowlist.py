from __future__ import annotations

from pathlib import Path

from skill_security.allowlist import apply_allowlist, load_allowlist
from skill_security.cli import main
from skill_security.scanner import scan_pack

FIXTURES = Path(__file__).parent / "fixtures"


def test_allowlist_accepts_known() -> None:
    al = load_allowlist(FIXTURES / "allowlist_test.json")
    ok, reason = al.check_skill(
        "no-futures-auto", source="Gruver87/dup-agent-skills"
    )
    assert ok, reason


def test_allowlist_denies_unknown() -> None:
    al = load_allowlist(FIXTURES / "allowlist_test.json")
    ok, _ = al.check_skill("evil-skill", source="Gruver87/dup-agent-skills")
    assert ok is False


def test_apply_on_bad_pack() -> None:
    report = scan_pack(FIXTURES / "bad_pack")
    al = load_allowlist(FIXTURES / "allowlist_test.json")
    denied = apply_allowlist(
        ["evil-skill"],
        al,
        source="Gruver87/dup-agent-skills",
        hashes=report.skill_hashes,
    )
    assert denied and denied[0][0] == "evil-skill"


def test_check_install_cli_refuses_bad() -> None:
    code = main(
        [
            "check-install",
            str(FIXTURES / "bad_pack"),
            "--allowlist",
            str(FIXTURES / "allowlist_test.json"),
        ]
    )
    assert code == 1


def test_check_install_cli_allows_good() -> None:
    code = main(
        [
            "check-install",
            str(FIXTURES / "good_pack"),
            "--allowlist",
            str(FIXTURES / "allowlist_test.json"),
        ]
    )
    assert code == 0
