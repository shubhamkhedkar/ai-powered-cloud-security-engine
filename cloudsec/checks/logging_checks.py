from botocore.exceptions import ClientError

from cloudsec.checks import check
from cloudsec.models import Finding, Severity


@check("CLOUDTRAIL", "cloudtrail")
def cloudtrail(session, region):
    ct = session.client("cloudtrail", region_name=region)
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    logging_ok = False
    for t in trails:
        try:
            if ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging"):
                logging_ok = True
                if not t.get("LogFileValidationEnabled"):
                    yield Finding("CT.2", "CloudTrail log file validation disabled", Severity.LOW, t["TrailARN"], region,
                                  f"Trail {t['Name']} does not validate log files.",
                                  "Enable log file validation.", ["CIS AWS 3.2", "AWS FSBP CloudTrail.4"], "cloudtrail")
        except ClientError:
            continue
    if not logging_ok:
        yield Finding("CT.1", "No active CloudTrail trail in region", Severity.HIGH, f"cloudtrail:{region}", region,
                      "No CloudTrail trail is logging API activity for this region.",
                      "Create a multi-region trail with log validation and KMS encryption.",
                      ["CIS AWS 3.1", "AWS FSBP CloudTrail.1"], "cloudtrail")


@check("GUARDDUTY", "guardduty")
def guardduty(session, region):
    gd = session.client("guardduty", region_name=region)
    ids = gd.list_detectors().get("DetectorIds", [])
    enabled = any(gd.get_detector(DetectorId=d).get("Status") == "ENABLED" for d in ids)
    if not enabled:
        yield Finding("GD.1", "GuardDuty not enabled", Severity.MEDIUM, f"guardduty:{region}", region,
                      "Amazon GuardDuty threat detection is not enabled in this region.",
                      "Enable GuardDuty (ideally organization-wide via delegated admin).",
                      ["AWS FSBP GuardDuty.1"], "guardduty")
