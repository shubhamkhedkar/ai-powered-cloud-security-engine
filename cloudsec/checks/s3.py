from botocore.exceptions import ClientError

from cloudsec.checks import check
from cloudsec.models import Finding, Severity


def _code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "")


@check("S3_BUCKETS", "s3", regional=False)
def s3_buckets(session, region):
    s3 = session.client("s3", region_name=region)
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        res = f"arn:aws:s3:::{name}"
        # Public access block
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            pab_ok = all(cfg.values())
        except ClientError as e:
            pab_ok = False if _code(e) == "NoSuchPublicAccessBlockConfiguration" else True
        if not pab_ok:
            yield Finding("S3.1", "S3 bucket Block Public Access not fully enabled", Severity.HIGH,
                          res, "global", f"Bucket {name} does not block all public access.",
                          "Enable all four S3 Block Public Access settings.",
                          ["CIS AWS 2.1.4", "AWS FSBP S3.8"], "s3")
        # ACL grants to everyone
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for g in acl.get("Grants", []):
                uri = g.get("Grantee", {}).get("URI", "")
                if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                    yield Finding("S3.2", "S3 bucket ACL grants public access", Severity.CRITICAL,
                                  res, "global", f"Bucket {name} ACL grants {g.get('Permission')} to {uri.rsplit('/',1)[-1]}.",
                                  "Remove public ACL grants and enable Object Ownership = BucketOwnerEnforced.",
                                  ["CIS AWS 2.1.4", "AWS FSBP S3.2"], "s3")
                    break
        except ClientError:
            pass
        # Encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if _code(e) == "ServerSideEncryptionConfigurationNotFoundError":
                yield Finding("S3.3", "S3 bucket default encryption not configured", Severity.MEDIUM,
                              res, "global", f"Bucket {name} has no default encryption configuration.",
                              "Enable default SSE-KMS or SSE-S3 encryption.",
                              ["CIS AWS 2.1.1", "AWS FSBP S3.4"], "s3")
        # Versioning
        try:
            if s3.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
                yield Finding("S3.4", "S3 bucket versioning disabled", Severity.LOW, res, "global",
                              f"Bucket {name} does not have versioning enabled.",
                              "Enable versioning (and consider MFA delete) to protect against deletion/ransomware.",
                              ["AWS FSBP S3.14"], "s3")
        except ClientError:
            pass
