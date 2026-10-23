import json
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from cloudsec.checks import check
from cloudsec.models import Finding, Severity

KEY_MAX_AGE_DAYS = 90


@check("IAM_ROOT_MFA", "iam", regional=False)
def root_mfa(session, region):
    iam = session.client("iam", region_name=region)
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) != 1:
        yield Finding("IAM.1", "Root account MFA not enabled", Severity.CRITICAL, "root-account", "global",
                      "The root user does not have MFA enabled.",
                      "Enable a hardware or virtual MFA device on the root user.",
                      ["CIS AWS 1.5", "AWS FSBP IAM.9"], "iam")
    if summary.get("AccountAccessKeysPresent", 0):
        yield Finding("IAM.2", "Root account has access keys", Severity.CRITICAL, "root-account", "global",
                      "Access keys exist for the root user.", "Delete root access keys.",
                      ["CIS AWS 1.4", "AWS FSBP IAM.4"], "iam")


@check("IAM_USERS", "iam", regional=False)
def iam_users(session, region):
    iam = session.client("iam", region_name=region)
    now = datetime.now(timezone.utc)
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            name, arn = u["UserName"], u["Arn"]
            has_console = True
            try:
                iam.get_login_profile(UserName=name)
            except ClientError:
                has_console = False
            if has_console and not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                yield Finding("IAM.3", "IAM user with console access has no MFA", Severity.HIGH, arn, "global",
                              f"User {name} can sign in to the console without MFA.",
                              "Enforce MFA for all console users.", ["CIS AWS 1.10", "AWS FSBP IAM.5"], "iam")
            for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                age = (now - k["CreateDate"]).days
                if k["Status"] == "Active" and age > KEY_MAX_AGE_DAYS:
                    yield Finding("IAM.4", "IAM access key older than 90 days", Severity.MEDIUM, arn, "global",
                                  f"User {name} has an active access key {age} days old.",
                                  "Rotate the access key and remove the old one.",
                                  ["CIS AWS 1.14", "AWS FSBP IAM.3"], "iam")


def _has_wildcard(doc) -> bool:
    if isinstance(doc, str):
        doc = json.loads(doc)
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Allow":
            continue
        acts = s.get("Action", [])
        res = s.get("Resource", [])
        acts = [acts] if isinstance(acts, str) else acts
        res = [res] if isinstance(res, str) else res
        if "*" in acts and "*" in res:
            return True
    return False


@check("IAM_WILDCARD", "iam", regional=False)
def wildcard_policies(session, region):
    iam = session.client("iam", region_name=region)
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for p in page["Policies"]:
            v = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])
            if _has_wildcard(v["PolicyVersion"]["Document"]):
                yield Finding("IAM.5", "Customer-managed policy grants full '*:*' admin", Severity.HIGH,
                              p["Arn"], "global", f"Policy {p['PolicyName']} allows Action '*' on Resource '*'.",
                              "Replace with least-privilege policies scoped to required actions/resources.",
                              ["CIS AWS 1.16", "AWS FSBP IAM.1"], "iam")
