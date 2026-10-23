from cloudsec.checks import check
from cloudsec.models import Finding, Severity


@check("EBS_ENCRYPTION", "ec2")
def ebs(session, region):
    ec2 = session.client("ec2", region_name=region)
    if not ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"):
        yield Finding("EBS.1", "EBS encryption by default disabled", Severity.MEDIUM, f"ebs-default:{region}", region,
                      "New EBS volumes in this region are not encrypted by default.",
                      "Enable EBS encryption by default for the region.", ["CIS AWS 2.2.1", "AWS FSBP EC2.7"], "ec2")
    for page in ec2.get_paginator("describe_volumes").paginate():
        for v in page["Volumes"]:
            if not v.get("Encrypted"):
                yield Finding("EBS.2", "Unencrypted EBS volume", Severity.MEDIUM, v["VolumeId"], region,
                              f"Volume {v['VolumeId']} is not encrypted.",
                              "Snapshot, copy with encryption, and replace the volume.", ["AWS FSBP EC2.3"], "ec2")


@check("RDS", "rds")
def rds(session, region):
    client = session.client("rds", region_name=region)
    for page in client.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            arn = db.get("DBInstanceArn", db["DBInstanceIdentifier"])
            if not db.get("StorageEncrypted"):
                yield Finding("RDS.1", "RDS instance storage not encrypted", Severity.HIGH, arn, region,
                              f"DB {db['DBInstanceIdentifier']} has unencrypted storage.",
                              "Restore from an encrypted snapshot copy.", ["CIS AWS 2.3.1", "AWS FSBP RDS.3"], "rds")
            if db.get("PubliclyAccessible"):
                yield Finding("RDS.2", "RDS instance publicly accessible", Severity.CRITICAL, arn, region,
                              f"DB {db['DBInstanceIdentifier']} is publicly accessible.",
                              "Set PubliclyAccessible=false and place in private subnets.",
                              ["CIS AWS 2.3.3", "AWS FSBP RDS.2"], "rds")


@check("KMS_ROTATION", "kms")
def kms_rotation(session, region):
    kms = session.client("kms", region_name=region)
    for page in kms.get_paginator("list_keys").paginate():
        for k in page["Keys"]:
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT" \
                    or meta.get("KeyState") != "Enabled":
                continue
            if not kms.get_key_rotation_status(KeyId=k["KeyId"]).get("KeyRotationEnabled"):
                yield Finding("KMS.1", "KMS key rotation disabled", Severity.LOW, meta["Arn"], region,
                              f"Customer managed key {k['KeyId']} does not have automatic rotation.",
                              "Enable automatic key rotation.", ["CIS AWS 3.6", "AWS FSBP KMS.4"], "kms")
