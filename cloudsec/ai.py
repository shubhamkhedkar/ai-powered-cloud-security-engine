"""AI analysis via any OpenAI-compatible Chat Completions API, with rule-based fallback."""
from __future__ import annotations

import json
import os
import re

import httpx

from cloudsec.models import Finding
from cloudsec.redact import redact_obj

SYSTEM = (
    "You are a senior AWS cloud security engineer. For each finding, return JSON with key 'results': a list of "
    "objects {index, priority (1=fix first), risk_score (0-100), explanation (plain English), attack_scenario, "
    "remediation_steps (list), cli_fix (AWS CLI snippet, use placeholders like <BUCKET>), terraform_fix}. "
    "Identifiers have been redacted; keep placeholders. Respond with JSON only."
)

FALLBACK_SCENARIOS = {
    "S3": "An attacker enumerates public buckets and downloads or overwrites sensitive objects.",
    "IAM": "Stolen or phished credentials give an attacker persistent, possibly admin-level access.",
    "EC2": "Internet scanners find the exposed service and brute-force or exploit it, or SSRF steals instance credentials.",
    "RDS": "The database endpoint is reachable/readable, enabling data theft if credentials leak.",
    "EBS": "Snapshots or volumes shared or accessed improperly expose data at rest.",
    "CT": "Attacker activity goes unrecorded, blocking detection and forensics.",
    "GD": "Malicious activity (crypto-mining, recon, credential abuse) goes undetected.",
    "KMS": "Long-lived key material increases impact of key compromise.",
}


class AIConfig:
    def __init__(self):
        self.api_key = os.getenv("AI_API_KEY")
        self.base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.model = os.getenv("AI_MODEL", "gpt-4o-mini")

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)


def _family(cid: str) -> str:
    return cid.replace("TF.", "").split(".")[0]


def rule_based(findings: list[Finding]) -> None:
    ordered = sorted(findings, key=lambda f: -f.severity.weight)
    for prio, f in enumerate(ordered, 1):
        f.ai = {
            "source": "rules",
            "priority": prio,
            "risk_score": f.severity.weight * 10,
            "explanation": f.description,
            "attack_scenario": FALLBACK_SCENARIOS.get(_family(f.check_id), "Misconfiguration increases attack surface."),
            "remediation_steps": [f.remediation],
            "cli_fix": "",
            "terraform_fix": "",
        }


def _payload(findings: list[Finding]) -> list[dict]:
    return redact_obj([
        {"index": i, "check_id": f.check_id, "title": f.title, "severity": f.severity.value, "service": f.service,
         "description": f.description, "compliance": f.compliance}
        for i, f in enumerate(findings)
    ])


def _parse(content: str) -> list[dict]:
    m = re.search(r"\{.*\}", content, re.S)
    data = json.loads(m.group(0) if m else content)
    return data.get("results", []) if isinstance(data, dict) else data


def analyze(findings: list[Finding], cfg: AIConfig | None = None, client: httpx.Client | None = None,
            batch: int = 20) -> str:
    """Annotate findings in-place. Returns 'ai' or 'rules'."""
    cfg = cfg or AIConfig()
    rule_based(findings)
    if not cfg.enabled or not findings:
        return "rules"
    client = client or httpx.Client(timeout=60)
    try:
        for start in range(0, len(findings), batch):
            chunk = findings[start:start + batch]
            resp = client.post(
                f"{cfg.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {cfg.api_key}"},
                json={"model": cfg.model, "temperature": 0.1,
                      "response_format": {"type": "json_object"},
                      "messages": [{"role": "system", "content": SYSTEM},
                                   {"role": "user", "content": json.dumps(_payload(chunk))}]},
            )
            resp.raise_for_status()
            for r in _parse(resp.json()["choices"][0]["message"]["content"]):
                idx = r.get("index")
                if isinstance(idx, int) and 0 <= idx < len(chunk):
                    chunk[idx].ai = {**chunk[idx].ai, **{k: v for k, v in r.items() if k != "index"}, "source": "ai"}
        return "ai"
    except (httpx.HTTPError, ValueError, KeyError) as e:
        for f in findings:
            f.ai["ai_error"] = str(e)[:200]
        return "rules"
