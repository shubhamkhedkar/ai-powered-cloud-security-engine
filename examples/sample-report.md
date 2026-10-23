# Cloud Security Report

- Generated: 2026-10-23T18:30:25+00:00
- Mode: iac
- Analysis: rules
- **Security score: 36/100**

| Severity | Count |
|---|---|
| CRITICAL | 2 |
| HIGH | 3 |
| MEDIUM | 2 |
| LOW | 1 |

## 1. [CRITICAL] S3 bucket uses public ACL

- **Check:** `TF.S3.1`  **Resource:** `examples/terraform/insecure.tf:1 aws_s3_bucket.data`  **Region:** iac
- **Compliance:** CIS AWS 2.1.4

**Why it matters:** Bucket ACL is public-read/public-read-write.

**Attack scenario:** An attacker enumerates public buckets and downloads or overwrites sensitive objects.

**Remediation:**
1. Use acl = "private" and Block Public Access.

## 2. [CRITICAL] RDS publicly accessible

- **Check:** `TF.RDS.2`  **Resource:** `examples/terraform/insecure.tf:16 aws_db_instance.db`  **Region:** iac
- **Compliance:** CIS AWS 2.3.3

**Why it matters:** publicly_accessible = true.

**Attack scenario:** The database endpoint is reachable/readable, enabling data theft if credentials leak.

**Remediation:**
1. Set publicly_accessible = false.

## 3. [HIGH] S3 bucket without public access block

- **Check:** `TF.S3.3`  **Resource:** `examples/terraform/insecure.tf:1 aws_s3_bucket.data`  **Region:** iac
- **Compliance:** CIS AWS 2.1.4

**Why it matters:** No aws_s3_bucket_public_access_block resource in this file.

**Attack scenario:** An attacker enumerates public buckets and downloads or overwrites sensitive objects.

**Remediation:**
1. Add aws_s3_bucket_public_access_block with all four flags true.

## 4. [HIGH] Security group open to the internet on sensitive port

- **Check:** `TF.EC2.1`  **Resource:** `examples/terraform/insecure.tf:6 aws_security_group.web`  **Region:** iac
- **Compliance:** CIS AWS 5.2

**Why it matters:** Ingress from 0.0.0.0/0 covers ports [22].

**Attack scenario:** Internet scanners find the exposed service and brute-force or exploit it, or SSRF steals instance credentials.

**Remediation:**
1. Restrict cidr_blocks to trusted ranges.

## 5. [HIGH] RDS storage not encrypted

- **Check:** `TF.RDS.1`  **Resource:** `examples/terraform/insecure.tf:16 aws_db_instance.db`  **Region:** iac
- **Compliance:** CIS AWS 2.3.1

**Why it matters:** storage_encrypted is not true.

**Attack scenario:** The database endpoint is reachable/readable, enabling data theft if credentials leak.

**Remediation:**
1. Set storage_encrypted = true.

## 6. [MEDIUM] S3 bucket without default encryption

- **Check:** `TF.S3.2`  **Resource:** `examples/terraform/insecure.tf:1 aws_s3_bucket.data`  **Region:** iac
- **Compliance:** CIS AWS 2.1.1

**Why it matters:** No server-side encryption configuration found.

**Attack scenario:** An attacker enumerates public buckets and downloads or overwrites sensitive objects.

**Remediation:**
1. Add aws_s3_bucket_server_side_encryption_configuration.

## 7. [MEDIUM] EC2 instance allows IMDSv1

- **Check:** `TF.EC2.2`  **Resource:** `examples/terraform/insecure.tf:22 aws_instance.app`  **Region:** iac
- **Compliance:** CIS AWS 5.6

**Why it matters:** metadata_options.http_tokens is not "required".

**Attack scenario:** Internet scanners find the exposed service and brute-force or exploit it, or SSRF steals instance credentials.

**Remediation:**
1. Add metadata_options { http_tokens = "required" }.

## 8. [LOW] KMS key rotation disabled

- **Check:** `TF.KMS.1`  **Resource:** `examples/terraform/insecure.tf:27 aws_kms_key.k`  **Region:** iac
- **Compliance:** CIS AWS 3.6

**Why it matters:** enable_key_rotation is not true.

**Attack scenario:** Long-lived key material increases impact of key compromise.

**Remediation:**
1. Set enable_key_rotation = true.
