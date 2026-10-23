from pathlib import Path

from cloudsec.iac import scan_path, scan_text


def test_insecure_example():
    f = scan_path(Path(__file__).parent.parent / "examples" / "terraform")
    got = {x.check_id for x in f}
    assert {"TF.S3.1", "TF.S3.3", "TF.EC2.1", "TF.RDS.1", "TF.RDS.2", "TF.EC2.2", "TF.KMS.1"} <= got


def test_secure_resources():
    tf = '''
resource "aws_kms_key" "k" { enable_key_rotation = true }
resource "aws_ebs_volume" "v" { encrypted = true }
resource "aws_instance" "i" {
  metadata_options { http_tokens = "required" }
}
resource "aws_security_group" "sg" {
  ingress {
    from_port = 443
    to_port = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
    assert scan_text(tf) == []


def test_iam_wildcard():
    tf = '''resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}'''
    assert [f.check_id for f in scan_text(tf)] == ["TF.IAM.1"]
