"""Undo the tricks attackers use to hide trigger words from a text filter.

`variants(text)` returns the text in several canonical forms. A detector runs
on every form, so "1gn0r3", "i g n o r e", look-alike Cyrillic letters, and
base64 / hex / rot13 wrapped payloads are all seen as plain words.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

_ZERO_WIDTH = re.compile(r"[​-‏⁠-⁤﻿­]")
# Cyrillic and Greek letters that look like Latin ones.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "һ": "h",
    "к": "k", "м": "m", "т": "t", "в": "b", "н": "h", "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "υ": "u",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_LEET_WORD = re.compile(r"\b(?=\w*[a-z])(?=\w*[013457@$!])[\w@$!]{3,}\b")
# Single characters split by a separator: "i g n o r e", "i.g.n.o.r.e", "d-i-s-r-e-g-a-r-d".
_SPACED = re.compile(r"\b(?:[a-z0-9][ .\-_*]){3,}[a-z0-9]\b")
_B64 = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){10,}\b")


def canonical(text: str, keep_lines: bool = False) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text).lower().translate(_HOMOGLYPHS)   # lower first: the map holds lowercase look-alikes
    if keep_lines:
        return re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _printable(data: bytes) -> str | None:
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(decoded) >= 8 and sum(ch.isalpha() or ch.isspace() for ch in decoded) / len(decoded) > 0.8:
        return decoded
    return None


def decoded_payloads(text: str) -> list[str]:
    """Readable text hidden inside base64 or hex runs."""
    found = []
    for match in _B64.findall(text):
        try:
            decoded = _printable(base64.b64decode(match + "=" * (-len(match) % 4), validate=True))
        except (binascii.Error, ValueError):
            decoded = None
        if decoded:
            found.append(decoded)
    for match in _HEX.findall(text):
        decoded = _printable(bytes.fromhex(match))
        if decoded:
            found.append(decoded)
    return found


def variants(text: str) -> list[tuple[str, str]]:
    """(name, text) pairs. "plain" is first; the rest are de-obfuscated forms."""
    plain = canonical(text)
    out = [("plain", plain)]

    def add(name: str, value: str) -> None:
        if value and all(value != existing for _, existing in out):
            out.append((name, value))

    add("unspaced", _SPACED.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), plain))
    add("leet", _LEET_WORD.sub(lambda m: m.group(0).translate(_LEET), plain))
    for payload in decoded_payloads(text):
        add("decoded", canonical(payload))
    add("rot13", canonical(codecs.decode(text, "rot13")))
    return out
