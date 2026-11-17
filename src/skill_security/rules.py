"""Heuristic security rules for skill text / scripts."""

from __future__ import annotations

import re
from dataclasses import dataclass

from skill_security.models import Severity


@dataclass(frozen=True)
class Rule:
    code: str
    pattern: re.Pattern[str]
    severity: Severity
    message: str


SECRET_RULES: tuple[Rule, ...] = (
    Rule(
        "aws_access_key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        Severity.ERROR,
        "possible AWS access key",
    ),
    Rule(
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        Severity.ERROR,
        "private key PEM block",
    ),
    Rule(
        "generic_api_key_assign",
        re.compile(
            r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)"
            r"\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"
        ),
        Severity.ERROR,
        "hardcoded API/secret assignment",
    ),
    Rule(
        "sk_live_token",
        re.compile(r"sk-(?:live|test|proj)-[A-Za-z0-9]{16,}"),
        Severity.ERROR,
        "sk-live/test style token",
    ),
    Rule(
        "jwt_like",
        re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
        Severity.ERROR,
        "JWT-like credential",
    ),
)

EXEC_RULES: tuple[Rule, ...] = (
    Rule(
        "download_exec",
        re.compile(
            r"(?i)(curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh"
            r"|(?:iwr|Invoke-WebRequest).*\|\s*iex"
            r"|Invoke-Expression\s*\(\s*\(Invoke-WebRequest"
        ),
        Severity.ERROR,
        "download-and-execute pattern",
    ),
    Rule(
        "eval_obfuscation",
        re.compile(
            r"(?i)\beval\s*\(\s*(?:base64|Buffer|bytes\.fromhex)"
            r"|\bexec\s*\(\s*(?:base64|compile\s*\()"
            r"|FromBase64String\s*\("
        ),
        Severity.ERROR,
        "obfuscated eval/exec / base64 decode exec",
    ),
    Rule(
        "hidden_exfil",
        re.compile(
            r"(?i)(?:curl|wget|Invoke-WebRequest|httpx\.post|requests\.post)"
            r".{0,80}(?:password|api[_-]?key|authorization|cookie|token)"
        ),
        Severity.ERROR,
        "possible credential exfiltration over HTTP",
    ),
)

POLICY_RULES: tuple[Rule, ...] = (
    Rule(
        "futures_auto_enable",
        re.compile(
            r"(?i)\b(?:enable|turn\s+on|unlock)\b.{0,40}\bfutures?\s+auto\b"
            r"|\bfutures?\s+auto\b.{0,40}\b(?:enable|true|= ?1)\b"
        ),
        Severity.ERROR,
        "futures auto enable language",
    ),
    Rule(
        "disable_tls_verify",
        re.compile(
            r"(?i)verify\s*=\s*False"
            r"|ssl\._create_unverified_context"
            r"|CURLOPT_SSL_VERIFYPEER\s*,\s*0"
        ),
        Severity.ERROR,
        "TLS verification disabled",
    ),
)

ALL_RULES: tuple[Rule, ...] = SECRET_RULES + EXEC_RULES + POLICY_RULES

# Futures enable is OK if refuse framing is adjacent — handled in scanner.
FUTURES_REFUSE = re.compile(
    r"(?i)\b(?:refuse|forbidden|never|block|FUTURES_BLOCK|out\s+of\s+scope)\b"
)

TEXT_GLOBS = ("*.md", "*.ps1", "*.py", "*.sh", "*.js", "*.ts", "*.json", "*.toml")
SKIP_PARTS = {".git", "__pycache__", ".ruff_cache", "node_modules", ".venv"}
