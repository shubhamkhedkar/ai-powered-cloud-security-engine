"""Lightweight rule-based Terraform (.tf) scanner. Regex/heuristic, not a full HCL parser."""
from __future__ import annotations

import re
from pathlib import Path

from cloudsec.models import Finding, Severity

BLOCK_RE = re.compile(r'resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{', re.M)


def _blocks(text: str):
    for m in BLOCK_RE.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        yield m.group(1), m.group(2), text[m.end():i - 1], text.count("\n", 0, m.start()) + 1


def _f(cid, title, sev, path, line, rtype, name, desc, fix, comp):
    return Finding(cid, title, sev, f"{path}:{line} {rtype}.{name}", "iac", desc, fix, comp, "terraform")


def scan_text(text: str, path: str = "<memory>") -> list[Finding]:
    out: list[Finding] = []
    all_types = {t for t, _, _, _ in _blocks(text)}
    for rtype, name, body, line in _blocks(text):
        if rtype == "aws_security_group" or rtype == "aws_security_group_rule" or rtype == "aws_vpc_security_group_ingress_rule":
            ingress = re.findall(r'ingress\s*\{(.*?)\}', body, re.S) if rtype == "aws_security_group" else [body]
            for ing in ingress:
                if rtype == "aws_security_group_rule" and 'type' in ing and '"egress"' in ing:
                    continue
                if re.search(r'"0\.0\.0\.0/0"|"::/0"', ing):
                    fp = re.search(r'from_port\s*=\s*(\d+)', ing)
                    tp = re.search(r'to_port\s*=\s*(\d+)', ing)
                    lo, hi = (int(fp.group(1)) if fp else 0), (int(tp.group(1)) if tp else 65535)
                    hits = [p for p in (22, 3389, 3306, 5432, 6379, 27017) if lo <= p <= hi or (lo == 0 and hi == 0)]
                    if hits:
                        out.append(_f("TF.EC2.1", "Security group open to the internet on sensitive port", Severity.HIGH,
                                      path, line, rtype, name, f"Ingress from 0.0.0.0/0 covers ports {hits}.",
                                      "Restrict cidr_blocks to trusted ranges.", ["CIS AWS 5.2"]))
        if rtype == "aws_s3_bucket":
            if re.search(r'acl\s*=\s*"public-read(-write)?"', body):
                out.append(_f("TF.S3.1", "S3 bucket uses public ACL", Severity.CRITICAL, path, line, rtype, name,
                              "Bucket ACL is public-read/public-read-write.", 'Use acl = "private" and Block Public Access.',
                              ["CIS AWS 2.1.4"]))
            if "server_side_encryption_configuration" not in body and \
                    "aws_s3_bucket_server_side_encryption_configuration" not in all_types:
                out.append(_f("TF.S3.2", "S3 bucket without default encryption", Severity.MEDIUM, path, line, rtype, name,
                              "No server-side encryption configuration found.",
                              "Add aws_s3_bucket_server_side_encryption_configuration.", ["CIS AWS 2.1.1"]))
            if "aws_s3_bucket_public_access_block" not in all_types:
                out.append(_f("TF.S3.3", "S3 bucket without public access block", Severity.HIGH, path, line, rtype, name,
                              "No aws_s3_bucket_public_access_block resource in this file.",
                              "Add aws_s3_bucket_public_access_block with all four flags true.", ["CIS AWS 2.1.4"]))
        if rtype == "aws_s3_bucket_acl" and re.search(r'"public-read', body):
            out.append(_f("TF.S3.1", "S3 bucket uses public ACL", Severity.CRITICAL, path, line, rtype, name,
                          "Bucket ACL is public.", 'Use acl = "private".', ["CIS AWS 2.1.4"]))
        if rtype in ("aws_db_instance", "aws_rds_cluster"):
            if not re.search(r'storage_encrypted\s*=\s*true', body):
                out.append(_f("TF.RDS.1", "RDS storage not encrypted", Severity.HIGH, path, line, rtype, name,
                              "storage_encrypted is not true.", "Set storage_encrypted = true.", ["CIS AWS 2.3.1"]))
            if re.search(r'publicly_accessible\s*=\s*true', body):
                out.append(_f("TF.RDS.2", "RDS publicly accessible", Severity.CRITICAL, path, line, rtype, name,
                              "publicly_accessible = true.", "Set publicly_accessible = false.", ["CIS AWS 2.3.3"]))
        if rtype == "aws_ebs_volume" and not re.search(r'encrypted\s*=\s*true', body):
            out.append(_f("TF.EBS.1", "EBS volume not encrypted", Severity.MEDIUM, path, line, rtype, name,
                          "encrypted is not true.", "Set encrypted = true.", ["CIS AWS 2.2.1"]))
        if rtype == "aws_instance":
            if not re.search(r'http_tokens\s*=\s*"required"', body):
                out.append(_f("TF.EC2.2", "EC2 instance allows IMDSv1", Severity.MEDIUM, path, line, rtype, name,
                              'metadata_options.http_tokens is not "required".',
                              'Add metadata_options { http_tokens = "required" }.', ["CIS AWS 5.6"]))
        if rtype == "aws_kms_key" and not re.search(r'enable_key_rotation\s*=\s*true', body):
            out.append(_f("TF.KMS.1", "KMS key rotation disabled", Severity.LOW, path, line, rtype, name,
                          "enable_key_rotation is not true.", "Set enable_key_rotation = true.", ["CIS AWS 3.6"]))
        if rtype in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"):
            flat = re.sub(r"\s", "", body)
            if re.search(r'"?Action"?[:=]\[?"\*"', flat) and re.search(r'"?Resource"?[:=]\[?"\*"', flat):
                out.append(_f("TF.IAM.1", "IAM policy grants '*' on '*'", Severity.HIGH, path, line, rtype, name,
                              "Wildcard admin policy.", "Scope actions and resources to least privilege.", ["CIS AWS 1.16"]))
        if rtype == "aws_cloudtrail" and re.search(r'enable_log_file_validation\s*=\s*false', body):
            out.append(_f("TF.CT.1", "CloudTrail log validation disabled", Severity.LOW, path, line, rtype, name,
                          "enable_log_file_validation = false.", "Set it to true.", ["CIS AWS 3.2"]))
    return out


def scan_path(path: str | Path) -> list[Finding]:
    p = Path(path)
    files = [p] if p.is_file() else sorted(p.rglob("*.tf"))
    out: list[Finding] = []
    for f in files:
        if ".terraform" in f.parts:
            continue
        out.extend(scan_text(f.read_text(encoding="utf-8", errors="ignore"), str(f)))
    return out
