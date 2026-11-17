"""Client for other services (the email triage API, the ops agent) to call the guardrail.

    guard = GuardrailClient("http://localhost:8100", api_key="...")
    check = guard.screen_input(email_body)
    if check["verdict"] == "block":
        ...route to human review...
    safe_text = check["text"]          # personal data and secrets already masked

It fails closed: if the guardrail cannot be reached, the answer is "block".
A safety check that silently lets everything through when it is down is not a
safety check.
"""
from __future__ import annotations

import httpx


class GuardrailClient:
    def __init__(self, base_url: str, api_key: str = "", timeout_s: float = 5.0, fail_closed: bool = True):
        self.base_url, self.timeout_s, self.fail_closed = base_url.rstrip("/"), timeout_s, fail_closed
        self.headers = {"X-API-Key": api_key} if api_key else {}

    def _post(self, path: str, payload: dict, stage: str) -> dict:
        try:
            r = httpx.post(f"{self.base_url}{path}", json=payload, headers=self.headers, timeout=self.timeout_s)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError):
            if not self.fail_closed:
                raise
            return {"request_id": "", "stage": stage, "verdict": "block", "score": 0.0, "techniques": [],
                    "obfuscated": False, "findings": ["guardrail_unavailable"], "masked": {}, "text": ""}

    def screen_input(self, text: str) -> dict:
        return self._post("/v1/screen/input", {"text": text}, "input")

    def screen_output(self, text: str, system_prompt: str | None = None) -> dict:
        return self._post("/v1/screen/output", {"text": text, "system_prompt": system_prompt}, "output")
