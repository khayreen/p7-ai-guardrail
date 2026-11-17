"""The "before" detector: a short list of well-known phrases, matched literally.

This is what a first attempt at a guardrail usually looks like. It is kept as
the baseline that the layered detector in injection.py is measured against.
"""
from __future__ import annotations

PHRASES = (
    "ignore all previous instructions",
    "ignore previous instructions",
    "disregard your",
    "system prompt",
    "developer mode",
    "jailbreak",
    "do anything now",
    "you are now",
    "no restrictions",
)


def detect(text: str) -> bool:
    lowered = text.lower()
    return any(phrase in lowered for phrase in PHRASES)
