"""Redaction applied to every payload before it is sent to the AI provider."""
from __future__ import annotations

import re

PATTERNS = [
    (re.compile(r"arn:aws[\w-]*:[^\s\"',]+"), "<ARN>"),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "<ACCESS_KEY_ID>"),
    (re.compile(r"(?i)(secret|password|token)[\"']?\s*[:=]\s*[\"']?[^\s\"',]+"), r"\1=<REDACTED>"),
    (re.compile(r"\b[A-Za-z0-9/+=]{40}\b"), "<SECRET>"),
    (re.compile(r"\b\d{12}\b"), "<ACCOUNT_ID>"),
    (re.compile(r"\b(sg|i|vol|vpc|subnet|db)-[0-9a-f]{8,17}\b"), r"\1-<ID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?\b"), lambda m: m.group(0) if m.group(0).startswith("0.0.0.0") else "<IP>"),
]


def redact(text: str) -> str:
    for pat, rep in PATTERNS:
        text = pat.sub(rep, text)
    return text


def redact_obj(obj):
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj
