"""Read-only AWS scanner. Only Describe/List/Get calls are issued."""
from __future__ import annotations

import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cloudsec.checks import load_all
from cloudsec.models import Finding

log = logging.getLogger(__name__)
DEFAULT_REGION = "ap-south-1"


def make_session(profile: str | None = None, region: str = DEFAULT_REGION):
    return boto3.Session(profile_name=profile, region_name=region)


def list_regions(session) -> list[str]:
    ec2 = session.client("ec2")
    return sorted(r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"])


def scan(session, regions: list[str], services: set[str] | None = None) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    for chk in load_all():
        if services and chk.service not in services:
            continue
        targets = regions if chk.regional else [regions[0]]
        for region in targets:
            try:
                findings.extend(chk.func(session, region))
            except (ClientError, BotoCoreError) as e:
                msg = f"{chk.id}@{region}: {e}"
                log.warning(msg)
                errors.append(msg)
    return findings, errors
