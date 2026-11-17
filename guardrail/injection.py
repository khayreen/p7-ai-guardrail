"""Layered prompt-injection detector.

Text is first de-obfuscated (normalize.py), then matched against rules grouped
by attack technique. Each technique has a weight; weights combine into one
score, so several weak signals add up while one weak signal alone does not
trip the filter.

This catches known shapes of attack. It cannot recognise a request that is
harmful only because of who is asking (see README, "What a filter cannot do").
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .normalize import canonical, variants

_VERB = (r"(?:ignore|disregard|forget|override|bypass|discard|drop|set aside|stop following|do not follow|don't follow|cancel|reset|abandon|"
         r"disable|turn off|switch off|deactivate|remove|lift)")
_TARGET = (r"(?:instruction|direction|directive|guideline|guidance|rule|prompt|polic(?:y|ies)|restriction|safety setting|"
           r"safeguard|filter|programming|training|constraint|policy text|system message)s?")

RULES: dict[str, list[str]] = {
    "override": [
        rf"\b{_VERB}\b.{{0,40}}\b(?:previous|prior|above|earlier|all|your|the|any|system|initial|original)\b.{{0,30}}\b{_TARGET}\b",
        rf"\b{_VERB}\b (?:everything|whatever|what) you (?:were|have been|are) (?:told|given|taught)",
        r"\b(?:new|updated|revised) (?:instructions|rules|directives)\s*:",
        rf"\b{_TARGET}\b.{{0,40}}\b(?:are|were|is|was|have been|has been)\b.{{0,15}}\b(?:outdated|a test|cancell?ed|void|replaced|obsolete)\b",
        rf"\b{_TARGET}\b.{{0,30}}\b(?:no longer|do not|don't|does not|doesn't) appl(?:y|ies)\b",
        r"\bfrom (?:now on|here|this point),? (?:on,? )?you\b",
        r"\byour (?:only|new|real|sole) (?:task|job|goal|purpose)\b",
        r"\b(?:obey|follow) only\b",
        r"\bwhatever you were told\b",
        r"\b(?:answer|respond|reply)\b.{0,20}\b(?:with no|without(?: any)?) (?:policy )?checks\b",
    ],
    "role_hijack": [
        r"\byou are now\b",
        r"\bdeveloper mode\b",
        r"\bjailbr(?:eak|oken)",
        r"\bdo anything now\b",
        r"\b(?:no|without(?: any)?|zero|free of|not bound by(?: any)?) (?:restrictions|filters|limitations|content policy|safeguards|rules|censorship|bank policy|polic(?:y|ies))\b",
        r"\b(?:unrestricted|unfiltered|uncensored)\b",
        r"\b(?:never|not) (?:refuses?|refusing)\b",
        r"\bno longer (?:a|an|the) (?:bank )?(?:assistant|chatbot|ai)\b",
        r"\bstay in character\b",
        r"\b(?:take on|assume|adopt) the (?:persona|role)\b",
    ],
    "prompt_extraction": [
        r"\b(?:reveal|show|print|repeat|output|display|disclose|paste|write out|tell|give|read|share|translate|summari[sz]e|recite)\b.{0,60}"
        r"\b(?:system (?:prompt|message)|initial prompt|hidden (?:instructions|rules|prompt)|your (?:instructions|rules|guidelines|prompt|configuration)|"
        r"(?:text|words|message) above|everything (?:above|written before)|configuration text|guidelines your)",
        r"\bwhat (?:is|are|was|were) your (?:system |initial |hidden )?(?:prompt|instructions)\b",
        r"\b(?:instructions|guidelines|rules|prompt) (?:you were given|your (?:creators|developers) gave)\b",
        r"\b(?:before|prior to) this conversation (?:started|began)\b",
        r"\bthe part i (?:cannot|can't|can not) see\b",
    ],
    "delimiter": [
        r"</?\s*(?:system|assistant|user|instructions?)\s*>",
        r"\[/?\s*(?:inst|system|sys)\s*\]",
        r"<<\s*/?sys\s*>>",
        r"<\|im_(?:start|end)\|>",
        r"^\s*#{2,}\s*(?:system|user|assistant)\b",
        r"^\s*(?:system|assistant|human)\s*:",
        r"\bend of (?:user )?(?:input|message|prompt)\b",
        r"```\s*system\b",
        r"<!--.{0,80}\b(?:system|assistant)\b",
    ],
    "exfiltration": [
        r"!\[[^\]]*\]\(https?://[^)\s]*\?",
        r"\b(?:send|forward|email|post|upload|transmit)\b.{0,80}\b(?:customer|chat|conversation|record|history|data|file|details|everything)s?\b.{0,80}"
        r"(?:https?://|\b[\w.+-]+@[\w-]+\.[\w.]+)",
        r"\b(?:send|forward|post|upload|call)\b.{0,40}(?:https?://)",
        r"https?://\S+[?&][\w-]+=",
        r"\b(?:append|add|include|attach|put)\b.{0,40}\b(?:api key|password|secret|token|credential)s?\b",
        r"\bencode\b.{0,40}\b(?:base64|hex)\b",
        r"\bwebhook\b",
    ],
    "action_coercion": [
        r"\b(?:without|skip|skipping|bypass|bypassing|no need (?:for|to)|there is no need)\b.{0,30}\b(?:verification|approval|review|otp|tac|checks?|authentication|human|identity)\b",
        r"\bno (?:review|verification|approval|checks?) (?:needed|required|necessary)\b",
        r"\b(?:do not|don't|dont|never)\b.{0,15}\b(?:flag|escalate|log|report|record|audit|notify|alert)\b (?:it|this|that|them|anyone|anything|to)\b",
        r"\b(?:keep|leave) (?:this|it) out of the (?:audit )?log\b",
        r"\bsuppress\b.{0,20}\b(?:alert|log|notification)s?\b",
        r"\bmark (?:this|it|the)\b.{0,20}\bas (?:safe|approved|verified|low)\b",
    ],
    "social_engineering": [
        r"\b(?:i am|i'm|this is|as) (?:the |your |a |an )?(?:bank's )?(?:developer|administrator|admin|creator|owner|ceo|engineer)\b",
        r"\b(?:it support|security team|i wrote your code)\b",
        r"\b(?:authori[sz]ed?|ordered|instructed)\b.{0,15}\b(?:by|you to|all)\b",
        r"\b(?:penetration test|pen test)\b",
        r"\b(?:for|needed for) (?:an? )?(?:debugging|audit|transparency)\b",
        r"\b(?:word for word|verbatim|exactly as written)\b",
    ],
    "multilingual": [
        r"\babaikan\b.{0,30}\barahan\b",
        r"\blupakan\b.{0,20}\barahan\b",
        r"\bjangan ikut\b.{0,30}\b(?:peraturan|arahan)\b",
        r"\b(?:tunjukkan|dedahkan|berikan|paparkan)\b.{0,30}\b(?:arahan sistem|prompt sistem)\b",
        r"\banda sekarang\b.{0,40}\b(?:tanpa|bebas)\b",
        r"\btanpa (?:pengesahan|kelulusan|semakan)\b",
        r"\bjangan (?:laporkan|maklumkan|rekodkan)\b",
        r"\bignora\b.{0,40}\binstrucciones\b",
        r"忽略.{0,12}(?:指示|指令|提示|规则)",
    ],
    "data_request": [
        r"\b(?:another|other|different|someone else's)\b.{0,20}\b(?:customer|person|account holder)",
        r"\bmy (?:neighbou?r|wife|husband|friend|boss|colleague)(?:'s)?\b.{0,40}\b(?:password|card number|cvv|balance|account)\b",
        r"\b(?:customer|caller) (?:who|that) (?:called|came|chatted) before\b",
        r"\b(?:password|card number|cvv|balance|address|ic number|account number)\b.{0,40}\b(?:for|of|belonging to) (?:my |an?)?(?:neighbou?r|wife|husband|friend|boss|colleague|other|another)\b",
        r"\b(?:all|every|last \w+|list (?:of|the)|which)\b.{0,20}\bcustomers?\b",
        r"\b(?:print|show|give|tell|export|dump|list|what is)\b.{0,40}\b(?:api keys?|secrets?|tokens|connection strings?|database password|db password|credentials)\b",
        r"\bdump\b.{0,30}\b(?:data|records|table|database)\b",
        r"\bcustomer (?:list|records|data|file)\b",
    ],
}
WEIGHTS = {
    "override": 0.8, "role_hijack": 0.7, "prompt_extraction": 0.75, "delimiter": 0.7, "exfiltration": 0.75,
    "multilingual": 0.8, "action_coercion": 0.5, "data_request": 0.5, "social_engineering": 0.3,
}
OBFUSCATION_BONUS = 0.3
# For text spelled out letter by letter ("i g n o r e  a l l ..."), word boundaries are
# gone once the separators are removed, so these run on the letters-only form.
_SPELLED = re.compile(r"\b(?:[a-z0-9][ .\-_*]{1,3}){5,}[a-z0-9]\b")
_COMPACT = {
    "override": re.compile(r"(?:ignore|disregard|forget|override|bypass)(?:all|any|the|your)*(?:previous|prior|above|earlier)?(?:instructions|rules|guidelines|prompt|restrictions)"),
    "prompt_extraction": re.compile(r"(?:reveal|show|print|repeat)(?:me)?(?:the|your)?(?:system|hidden|initial)?(?:prompt|rules|instructions)"),
}
_COMPILED = {name: [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns] for name, patterns in RULES.items()}


@dataclass
class Detection:
    score: float = 0.0
    techniques: list[str] = field(default_factory=list)
    obfuscated: bool = False


def detect(text: str) -> Detection:
    lined = canonical(text, keep_lines=True)   # line starts matter for delimiter rules
    hits: set[str] = set()
    obfuscated = False
    for name, form in variants(text):
        for technique, patterns in _COMPILED.items():
            if technique in hits:
                continue
            haystack = lined if (technique == "delimiter" and name == "plain") else form
            if any(p.search(haystack) for p in patterns):
                hits.add(technique)
                obfuscated = obfuscated or name != "plain"
    plain = canonical(text)
    if _SPELLED.search(plain):
        letters = re.sub(r"[^a-z0-9]", "", plain)
        for technique, pattern in _COMPACT.items():
            if technique not in hits and pattern.search(letters):
                hits.add(technique)
                obfuscated = True
    remaining = 1.0
    for technique in hits:
        remaining *= 1 - WEIGHTS[technique]
    if obfuscated:
        remaining *= 1 - OBFUSCATION_BONUS
    return Detection(round(1 - remaining, 3), sorted(hits), obfuscated)
