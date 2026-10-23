from cloudsec.checks import check
from cloudsec.models import Finding, Severity

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
                   6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 23: "Telnet", 445: "SMB"}


def _covers(perm, port) -> bool:
    if perm.get("IpProtocol") == "-1":
        return True
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    return lo is not None and hi is not None and lo <= port <= hi


@check("EC2_SG_OPEN", "ec2")
def open_security_groups(session, region):
    ec2 = session.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                public = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or \
                    any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                if not public:
                    continue
                exposed = [f"{n}({p})" for p, n in SENSITIVE_PORTS.items() if _covers(perm, p)]
                if exposed:
                    sev = Severity.CRITICAL if perm.get("IpProtocol") == "-1" else Severity.HIGH
                    yield Finding("EC2.1", "Security group allows internet ingress to sensitive ports", sev,
                                  sg["GroupId"], region,
                                  f"Security group {sg['GroupId']} allows 0.0.0.0/0 to {', '.join(exposed)}.",
                                  "Restrict ingress to known CIDRs, or use SSM Session Manager / VPN instead.",
                                  ["CIS AWS 5.2", "CIS AWS 5.3", "AWS FSBP EC2.19"], "ec2")


@check("EC2_IMDSV1", "ec2")
def imdsv1(session, region):
    ec2 = session.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_instances").paginate():
        for r in page["Reservations"]:
            for i in r["Instances"]:
                if i.get("State", {}).get("Name") == "terminated":
                    continue
                if i.get("MetadataOptions", {}).get("HttpTokens") != "required":
                    yield Finding("EC2.2", "EC2 instance allows IMDSv1", Severity.MEDIUM, i["InstanceId"], region,
                                  f"Instance {i['InstanceId']} does not require IMDSv2 session tokens (SSRF credential theft risk).",
                                  "Set HttpTokens=required via modify-instance-metadata-options.",
                                  ["CIS AWS 5.6", "AWS FSBP EC2.8"], "ec2")
