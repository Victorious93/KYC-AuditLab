"""Best-effort redaction of obvious PII / secrets before anything is persisted.

This is a safety net, not a guarantee: it catches well-structured patterns
(emails, card numbers, SSNs, IBANs, international phone numbers, JWTs and
bearer tokens). Modules must still avoid capturing PII they don't need.
"""
from __future__ import annotations

import re
from typing import Optional

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
_PHONE = re.compile(r"(?<![\w+])\+\d[\d \-()]{6,18}\d\b")
_CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


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


def _card_sub(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    if 13 <= len(digits) <= 19 and _luhn_ok(digits):
        return "[REDACTED:card]"
    return m.group(0)


def redact(text: Optional[str]) -> Optional[str]:
    """Return `text` with obvious PII/secrets replaced by [REDACTED:<kind>]."""
    if not text:
        return text
    text = _JWT.sub("[REDACTED:jwt]", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} [REDACTED:token]", text)
    text = _EMAIL.sub("[REDACTED:email]", text)
    text = _SSN.sub("[REDACTED:ssn]", text)
    text = _IBAN.sub("[REDACTED:iban]", text)
    text = _CARD.sub(_card_sub, text)
    text = _PHONE.sub("[REDACTED:phone]", text)
    return text
