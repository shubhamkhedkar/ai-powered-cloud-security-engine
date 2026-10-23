resource "aws_s3_bucket" "data" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
}

resource "aws_instance" "app" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
}

resource "aws_kms_key" "k" {
  description = "app key"
}
