"""Mask personal data and secrets before text is stored, logged or sent onward.

Personal data is tuned for Malaysian formats: MyKad (IC) numbers, phone numbers,
payment cards, bank accounts, passports and email addresses. Secrets cover API
keys, private keys, tokens, passwords in assignments and connection strings.
Masking is one-way: the placeholder carries the type, never the value.
"""
from __future__ import annotations

import logging
import re
from collections import Counter

_SECRETS = [
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z ]+ )?PRIVATE KEY-----|$)"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|gsk|pk|rk)[-_][A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]+@[^\s]+", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z])(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token)\s*[:=]\s*[\"']?[^\s\"',;]{6,}", re.IGNORECASE),
    # "the password is X": only when X looks like a credential (has a digit or symbol), not an ordinary word.
    re.compile(r"(?<![A-Za-z])(?:password|passwd|pwd|secret|api[_-]?key|token) is\s+[\"']?(?=[^\s\"',;]*[\d!@#$%^&*_-])[^\s\"',;]{6,}", re.IGNORECASE),
]
# 13-19 digits, optionally grouped by spaces or dashes.
_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
# MyKad: YYMMDD-PB-###G, dashes or spaces optional.
_IC = re.compile(r"(?<!\d)(\d{2})(\d{2})(\d{2})[- ]?(\d{2})[- ]?(\d{4})(?!\d)")
# Mobile (+60 1x / 01x) and landline (0x-xxxxxxx).
_PHONE = re.compile(
    r"(?<![\d-])(?:\+?60[- ]?|0)(?:1\d[- ]?\d{3,4}[- ]?\d{4}|[3-9][- ]?\d{3,4}[- ]?\d{4})(?!\d)"
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PASSPORT = re.compile(r"\b[AHK]\d{8}\b")
# Any remaining long digit run is treated as an account/reference number.
_ACCOUNT = re.compile(r"(?<![\d-])\d(?:[ -]?\d){8,16}(?![\d-])")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _valid_ic(m: re.Match[str]) -> bool:
    month, day = int(m.group(2)), int(m.group(3))
    return 1 <= month <= 12 and 1 <= day <= 31


def mask(text: str) -> tuple[str, dict[str, int]]:
    """Return (masked_text, counts_by_type). Counts hold no personal data."""
    counts: Counter[str] = Counter()

    def sub(pattern: re.Pattern[str], label: str, check=None):
        nonlocal text

        def repl(m: re.Match[str]) -> str:
            if check is not None and not check(m):
                return m.group(0)
            counts[label] += 1
            return f"[{label}]"

        text = pattern.sub(repl, text)

    for pattern in _SECRETS:
        sub(pattern, "SECRET")
    sub(_EMAIL, "EMAIL")
    sub(_CARD, "CARD", lambda m: _luhn_ok(re.sub(r"\D", "", m.group(0))))
    sub(_IC, "IC", _valid_ic)
    sub(_PHONE, "PHONE")
    sub(_PASSPORT, "PASSPORT")
    sub(_ACCOUNT, "ACCOUNT")
    return text, dict(counts)


_installed = False


def install_log_masking() -> None:
    """Defence in depth: mask every log record at creation, for every logger and
    handler in the process, so a careless `log.info(email.body)` cannot leak."""
    global _installed
    if _installed:
        return
    previous = logging.getLogRecordFactory()

    def clean(value):
        # Numbers and None cannot be reformatted into personal data; everything
        # else is masked as text. Argument positions are preserved, because some
        # formatters (uvicorn's access log) read them by index.
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return mask(str(value))[0]

    def factory(*args, **kwargs) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        try:
            if isinstance(record.msg, str):
                record.msg = mask(record.msg)[0]
            if isinstance(record.args, dict):
                record.args = {k: clean(v) for k, v in record.args.items()}
            elif record.args:
                record.args = tuple(clean(a) for a in record.args)
        except Exception:  # never let masking break logging
            record.msg, record.args = "[log message withheld: masking failed]", ()
        return record

    logging.setLogRecordFactory(factory)
    _installed = True
