import json

import httpx

from cloudsec import report
from cloudsec.ai import AIConfig, analyze
from cloudsec.models import Finding, Severity, security_score
from cloudsec.redact import redact


def _findings():
    return [
        Finding("S3.4", "versioning", Severity.LOW, "arn:aws:s3:::b", "global", "Bucket b in 123456789012", "fix", ["x"], "s3"),
        Finding("RDS.2", "public db", Severity.CRITICAL, "arn:aws:rds:ap-south-1:123456789012:db:x", "ap-south-1",
                "DB x is public, key AKIAABCDEFGHIJKLMNOP", "fix", ["y"], "rds"),
    ]


def test_redaction():
    s = redact("arn:aws:iam::123456789012:user/bob AKIAABCDEFGHIJKLMNOP 123456789012 sg-0123456789abcdef0 password=hunter2")
    assert "123456789012" not in s and "AKIA" not in s and "hunter2" not in s and "0123456789abcdef0" not in s


def test_fallback_without_key(monkeypatch):
    monkeypatch.delenv("AI_API_KEY", raising=False)
    f = _findings()
    assert analyze(f) == "rules"
    assert f[1].ai["priority"] == 1 and f[1].ai["source"] == "rules"


def test_ai_mocked_and_redacted(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    sent = {}

    def handler(request: httpx.Request):
        sent["body"] = request.content.decode()
        sent["url"] = str(request.url)
        content = json.dumps({"results": [
            {"index": 1, "priority": 1, "risk_score": 95, "explanation": "Public DB", "attack_scenario": "scan",
             "remediation_steps": ["make private"], "cli_fix": "aws rds modify-db-instance --no-publicly-accessible",
             "terraform_fix": "publicly_accessible = false"},
            {"index": 0, "priority": 2, "risk_score": 10, "explanation": "meh", "attack_scenario": "",
             "remediation_steps": ["enable"], "cli_fix": "", "terraform_fix": ""}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    f = _findings()
    mode = analyze(f, AIConfig(), httpx.Client(transport=httpx.MockTransport(handler)))
    assert mode == "ai"
    assert sent["url"] == "https://api.openai.com/v1/chat/completions"
    assert "123456789012" not in sent["body"] and "arn:aws" not in sent["body"] and "AKIA" not in sent["body"]
    assert f[1].ai["source"] == "ai" and f[1].ai["risk_score"] == 95


def test_ai_error_falls_back(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    f = _findings()
    assert analyze(f, AIConfig(), client) == "rules"
    assert "ai_error" in f[0].ai


def test_reports_and_score():
    f = _findings()
    analyze(f, AIConfig())
    rep = report.build(f, "aws", "rules")
    assert rep["score"] == security_score(f) and 0 < rep["score"] < 100
    assert rep["findings"][0]["check_id"] == "RDS.2"
    assert "Security score" in report.to_markdown(rep)
    assert "<html>" in report.to_html(rep)
    assert json.loads(report.to_json(rep))["summary"] == {"LOW": 1, "CRITICAL": 1}
    assert security_score([]) == 100


def test_cli_iac(tmp_path):
    from cloudsec.cli import main
    out = tmp_path / "r.json"
    rc = main(["iac", "examples/terraform", "--no-ai", "--json", str(out), "--fail-on", "CRITICAL"])
    assert rc == 2 and json.loads(out.read_text())["findings"]


def test_dashboard(tmp_path):
    from fastapi.testclient import TestClient

    from cloudsec.dashboard import create_app
    p = tmp_path / "r.json"
    p.write_text(report.to_json(report.build(_findings(), "aws", "rules")))
    c = TestClient(create_app(str(p)))
    assert c.get("/").status_code == 200 and c.get("/api/report").json()["mode"] == "aws"
