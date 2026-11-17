"""The screening decisions. No web framework here, so it can be imported and
used directly, or served by service.py.

Input stage:  de-obfuscate -> injection score -> mask personal data and secrets.
Output stage: canary and prompt-leak check -> secrets -> credential requests ->
              links -> mask personal data.
"""
from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass, field

from . import injection
from .normalize import canonical
from .pii import mask
from .schemas import ScreenResult, Verdict

_URL = re.compile(r"(?:https?://|www\.)[^\s)>\]]+", re.IGNORECASE)
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\((?:https?://)[^)]*\)", re.IGNORECASE)
_CREDENTIAL_WORDS = r"(?:password|passcode|pin|otp|tac|cvv|security code|secure word)"
_ASK_WORDS = r"(?:send|share|provide|give|tell|reply with|enter|type|confirm|read out)"
_CREDENTIAL_ASK = re.compile(
    rf"\b{_ASK_WORDS}\b.{{0,40}}\byour\b.{{0,20}}\b{_CREDENTIAL_WORDS}\b|\byour\b.{{0,10}}\b{_CREDENTIAL_WORDS}\b.{{0,30}}\b{_ASK_WORDS}\b",
    re.IGNORECASE,
)
LEAK_WINDOW = 60  # characters of system prompt that count as a leak if repeated


@dataclass
class Settings:
    flag_threshold: float = 0.45
    block_threshold: float = 0.70
    strict: bool = False                      # strict: flagged input is blocked too
    allowed_link_domains: tuple[str, ...] = ()
    canary: str = field(default_factory=lambda: "CANARY-" + secrets.token_hex(8))


def _request_id() -> str:
    return uuid.uuid4().hex[:12]


def screen_input(text: str, settings: Settings) -> ScreenResult:
    detection = injection.detect(text)
    if detection.score >= settings.block_threshold or (settings.strict and detection.score >= settings.flag_threshold):
        verdict = Verdict.block
    elif detection.score >= settings.flag_threshold:
        verdict = Verdict.flag
    else:
        verdict = Verdict.allow
    masked_text, counts = mask(text)
    findings = ["prompt_injection"] if verdict is not Verdict.allow else []
    return ScreenResult(
        request_id=_request_id(), stage="input", verdict=verdict, score=detection.score,
        techniques=detection.techniques, obfuscated=detection.obfuscated, findings=findings,
        masked=counts, text=masked_text,
    )


def _domain(url: str) -> str:
    host = re.sub(r"^(?:https?://)?(?:www\.)?", "", url, flags=re.IGNORECASE)
    return re.split(r"[/:?#]", host, maxsplit=1)[0].lower().rstrip(".")


def _leaks_prompt(output: str, system_prompt: str | None) -> bool:
    if not system_prompt:
        return False
    prompt, out = canonical(system_prompt), canonical(output)
    if len(prompt) < LEAK_WINDOW:
        return len(prompt) >= 20 and prompt in out
    return any(prompt[i:i + LEAK_WINDOW] in out for i in range(0, len(prompt) - LEAK_WINDOW + 1, 10))


_NEGATION = re.compile(r"\b(?:never|not|don't|dont|won't|wont|cannot|can't|no one|nobody)\b", re.IGNORECASE)


def _asks_for_credentials(text: str) -> bool:
    """True if the text asks the reader for a password, PIN or OTP. Safety advice
    ("never share your PIN") uses the same words, so a negation nearby rules it out."""
    for match in _CREDENTIAL_ASK.finditer(text):
        window = text[max(0, match.start() - 40):match.end()]
        if not _NEGATION.search(window):
            return True
    return False


def screen_output(text: str, settings: Settings, system_prompt: str | None = None) -> ScreenResult:
    block: list[str] = []
    flag: list[str] = []
    if settings.canary in text or _leaks_prompt(text, system_prompt):
        block.append("system_prompt_leak")
    if _MD_IMAGE.search(text):
        block.append("external_image")          # a classic channel for leaking data in the URL
    if _asks_for_credentials(text):
        block.append("credential_request")

    def strip_link(match: re.Match[str]) -> str:
        domain = _domain(match.group(0))
        if any(domain == d or domain.endswith("." + d) for d in settings.allowed_link_domains):
            return match.group(0)
        if "unapproved_link" not in flag:
            flag.append("unapproved_link")
        return "[link removed]"

    cleaned = _URL.sub(strip_link, text)
    cleaned, counts = mask(cleaned)
    if counts.get("SECRET"):
        block.append("secret_in_output")
    if any(k != "SECRET" for k in counts):
        flag.append("personal_data_masked")

    verdict = Verdict.block if block else Verdict.flag if flag else Verdict.allow
    return ScreenResult(request_id=_request_id(), stage="output", verdict=verdict, findings=block + flag, masked=counts, text=cleaned)
