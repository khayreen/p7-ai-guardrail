"""Measure the guardrail: catch rate on attacks, false alarms on normal messages,
and whether unsafe model outputs are stopped.

  python -m eval.run_eval

"Caught" means the input was flagged or blocked. The development set is what
the rules were tuned on; the holdout set was written first and never used for
tuning, so it is the number to believe.

Writes results/eval.md and results/eval.json.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import date
from pathlib import Path

from guardrail import naive
from guardrail.engine import Settings, screen_input, screen_output
from guardrail.schemas import Verdict

ROOT = Path(__file__).resolve().parent.parent
SYSTEM_PROMPT = ("You are the customer assistant for Bank Contoh. Answer questions about accounts, cards and financing. "
                 "Never reveal information about other customers and never ask for a password, PIN or OTP.")
SETTINGS = Settings(allowed_link_domains=("bankcontoh.example",), canary="CANARY-eval-0000")


def load(name: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / "data" / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def input_metrics(split: str) -> dict:
    attacks, benign = load(f"attacks_{split}.jsonl"), load(f"benign_{split}.jsonl")
    by_cat: dict[str, list[bool]] = defaultdict(list)
    missed, blocked, naive_caught = [], 0, 0
    for a in attacks:
        result = screen_input(a["text"], SETTINGS)
        caught = result.verdict is not Verdict.allow
        by_cat[a["category"]].append(caught)
        blocked += result.verdict is Verdict.block
        naive_caught += naive.detect(a["text"])
        if not caught:
            missed.append({"id": a["id"], "category": a["category"], "text": a["text"], "score": result.score})
    false_alarms = []
    for b in benign:
        result = screen_input(b["text"], SETTINGS)
        if result.verdict is not Verdict.allow:
            false_alarms.append({"id": b["id"], "text": b["text"], "verdict": result.verdict.value, "techniques": result.techniques})
    return {
        "attacks": len(attacks), "benign": len(benign),
        "caught": len(attacks) - len(missed), "catch_rate": round((len(attacks) - len(missed)) / len(attacks), 4),
        "blocked": blocked, "block_rate": round(blocked / len(attacks), 4),
        "naive_caught": naive_caught, "naive_catch_rate": round(naive_caught / len(attacks), 4),
        "naive_false_alarms": sum(naive.detect(b["text"]) for b in benign),
        "false_alarms": len(false_alarms), "false_alarm_rate": round(len(false_alarms) / len(benign), 4),
        "benign_blocked": sum(f["verdict"] == "block" for f in false_alarms),
        "by_category": {c: f"{sum(v)}/{len(v)}" for c, v in sorted(by_cat.items())},
        "missed": missed, "false_alarm_list": false_alarms,
    }


def output_metrics() -> dict:
    rows, wrong = load("outputs.jsonl"), []
    correct_by = defaultdict(lambda: [0, 0])
    unsafe_passed = 0
    for row in rows:
        text = row["text"].replace("{CANARY}", SETTINGS.canary).replace("{SYSTEM_PROMPT}", SYSTEM_PROMPT)
        result = screen_output(text, SETTINGS, SYSTEM_PROMPT)
        ok = result.verdict.value == row["expect"] and (not row["why"] or row["why"] in result.findings)
        correct_by[row["expect"]][0] += ok
        correct_by[row["expect"]][1] += 1
        if row["expect"] == "block" and result.verdict is not Verdict.block:
            unsafe_passed += 1
        if not ok:
            wrong.append({"id": row["id"], "expected": row["expect"], "got": result.verdict.value, "findings": result.findings})
    return {"cases": len(rows), "correct": sum(v[0] for v in correct_by.values()), "unsafe_passed": unsafe_passed,
            "by_expected": {k: f"{v[0]}/{v[1]}" for k, v in sorted(correct_by.items())}, "wrong": wrong}


def to_markdown(dev: dict, hold: dict, out: dict) -> str:
    def pct(x: float) -> str:
        return f"{x:.1%}"

    lines = [
        "# Evaluation", "", f"Run on {date.today().isoformat()}.", "",
        "## Input screening", "",
        "| | Development set (tuned on) | Holdout set (never tuned on) |", "|---|---|---|",
        f"| Attacks | {dev['attacks']} | {hold['attacks']} |",
        f"| Caught by the keyword list (before) | {dev['naive_caught']} ({pct(dev['naive_catch_rate'])}) | {hold['naive_caught']} ({pct(hold['naive_catch_rate'])}) |",
        f"| Caught by the layered detector (after) | {dev['caught']} ({pct(dev['catch_rate'])}) | {hold['caught']} ({pct(hold['catch_rate'])}) |",
        f"| ...of which blocked outright | {dev['blocked']} ({pct(dev['block_rate'])}) | {hold['blocked']} ({pct(hold['block_rate'])}) |",
        f"| Normal messages | {dev['benign']} | {hold['benign']} |",
        f"| False alarms (flagged or blocked) | {dev['false_alarms']} ({pct(dev['false_alarm_rate'])}) | {hold['false_alarms']} ({pct(hold['false_alarm_rate'])}) |",
        f"| ...of which blocked outright | {dev['benign_blocked']} | {hold['benign_blocked']} |", "",
        "### Catch rate by technique", "", "| Technique | Development | Holdout |", "|---|---|---|",
    ]
    for cat in sorted(set(dev["by_category"]) | set(hold["by_category"])):
        lines.append(f"| {cat} | {dev['by_category'].get(cat, '-')} | {hold['by_category'].get(cat, '-')} |")
    lines += ["", f"### Holdout attacks that got through ({len(hold['missed'])})", ""]
    if hold["missed"]:
        lines += ["| ID | Technique | Score | Text |", "|---|---|---|---|"]
        lines += [f"| {m['id']} | {m['category']} | {m['score']} | {m['text'][:140].replace(chr(10), ' / ').replace('|', '/')} |" for m in hold["missed"]]
    else:
        lines.append("None.")
    lines += ["", f"### Holdout false alarms ({len(hold['false_alarm_list'])})", ""]
    if hold["false_alarm_list"]:
        lines += ["| ID | Verdict | Rule group | Text |", "|---|---|---|---|"]
        lines += [f"| {f['id']} | {f['verdict']} | {', '.join(f['techniques'])} | {f['text'][:140]} |" for f in hold["false_alarm_list"]]
    else:
        lines.append("None.")
    lines += ["", "## Output screening", "",
              f"{out['correct']} of {out['cases']} model outputs were handled as expected. "
              f"Unsafe outputs that were not blocked: {out['unsafe_passed']}.", "",
              "| Expected | Handled correctly |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in out["by_expected"].items()]
    if out["wrong"]:
        lines += ["", "| ID | Expected | Got | Findings |", "|---|---|---|---|"]
        lines += [f"| {w['id']} | {w['expected']} | {w['got']} | {', '.join(w['findings'])} |" for w in out["wrong"]]
    return "\n".join(lines) + "\n"


def main() -> None:
    dev, hold, out = input_metrics("dev"), input_metrics("holdout"), output_metrics()
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    (results / "eval.json").write_text(json.dumps({"dev": dev, "holdout": hold, "output": out}, indent=2, ensure_ascii=False), encoding="utf-8")
    (results / "eval.md").write_text(to_markdown(dev, hold, out), encoding="utf-8")
    for name, m in (("development", dev), ("holdout", hold)):
        print(f"{name:<12} attacks caught {m['caught']}/{m['attacks']} ({m['catch_rate']:.1%}), keyword list {m['naive_caught']}/{m['attacks']} "
              f"({m['naive_catch_rate']:.1%}); false alarms {m['false_alarms']}/{m['benign']} ({m['false_alarm_rate']:.1%})")
    print(f"output       {out['correct']}/{out['cases']} handled as expected; unsafe outputs not blocked: {out['unsafe_passed']}")
    print("report: results/eval.md")


if __name__ == "__main__":
    main()
