import json

from cloudsec.scanner import scan

R = "ap-south-1"


def ids(findings):
    return {f.check_id for f in findings}


def test_s3_insecure_bucket(aws):
    s3 = aws.client("s3", region_name=R)
    s3.create_bucket(Bucket="bad", CreateBucketConfiguration={"LocationConstraint": R})
    s3.put_bucket_acl(Bucket="bad", ACL="public-read")
    f, errors = scan(aws, [R], {"s3"})
    assert {"S3.1", "S3.2", "S3.4"} <= ids(f)
    assert not errors


def test_s3_secure_bucket(aws):
    s3 = aws.client("s3", region_name=R)
    s3.create_bucket(Bucket="good", CreateBucketConfiguration={"LocationConstraint": R})
    s3.put_public_access_block(Bucket="good", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_encryption(Bucket="good", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    s3.put_bucket_versioning(Bucket="good", VersioningConfiguration={"Status": "Enabled"})
    f, _ = scan(aws, [R], {"s3"})
    assert not ids(f) & {"S3.1", "S3.2", "S3.3", "S3.4"}


def test_iam(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Xx-123456789!")
    iam.create_policy(PolicyName="admin", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    f, _ = scan(aws, [R], {"iam"})
    assert {"IAM.1", "IAM.3", "IAM.5"} <= ids(f)


def test_security_group_and_imds(aws):
    ec2 = aws.client("ec2", region_name=R)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="open", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1,
                      MetadataOptions={"HttpTokens": "optional"})
    f, _ = scan(aws, [R], {"ec2"})
    sg_f = [x for x in f if x.check_id == "EC2.1"]
    assert sg_f and sg_f[0].resource == sg and "SSH" in sg_f[0].description
    assert "EC2.2" in ids(f)


def test_rds_kms_logging(aws):
    rds = aws.client("rds", region_name=R)
    rds.create_db_instance(DBInstanceIdentifier="db1", DBInstanceClass="db.t3.micro", Engine="postgres",
                           MasterUsername="u", MasterUserPassword="password123", AllocatedStorage=20,
                           PubliclyAccessible=True, StorageEncrypted=False)
    aws.client("kms", region_name=R).create_key()
    f, _ = scan(aws, [R], {"rds", "kms", "cloudtrail", "guardduty"})
    assert {"RDS.1", "RDS.2", "KMS.1", "CT.1", "GD.1"} <= ids(f)


def test_guardduty_enabled_clears_finding(aws):
    aws.client("guardduty", region_name=R).create_detector(Enable=True)
    f, _ = scan(aws, [R], {"guardduty"})
    assert "GD.1" not in ids(f)
