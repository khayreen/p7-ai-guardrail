from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

MAX_TEXT = 20_000


class Verdict(str, Enum):
    allow = "allow"   # pass through
    flag = "flag"     # pass through, but record it and route to review
    block = "block"   # do not pass through


class ScreenIn(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT)


class OutputIn(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT)
    system_prompt: str | None = Field(default=None, max_length=MAX_TEXT)


class ScreenResult(BaseModel):
    request_id: str
    stage: str                      # "input" or "output"
    verdict: Verdict
    score: float = 0.0              # injection score, 0 to 1 (input stage)
    techniques: list[str] = Field(default_factory=list)
    obfuscated: bool = False
    findings: list[str] = Field(default_factory=list)
    masked: dict[str, int] = Field(default_factory=dict)
    text: str                       # the text that may be passed on: personal data and secrets masked


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_TEXT)
    system_prompt: str = Field(default="You are a helpful assistant for a retail bank's customers.", max_length=MAX_TEXT)


class ChatOut(BaseModel):
    request_id: str
    blocked: bool
    blocked_at: str | None = None   # "input" or "output"
    reply: str
    input: ScreenResult
    output: ScreenResult | None = None
