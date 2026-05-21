provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.s0/0"] 
  }
}

resource "aws_db_instance" "db" {
  identifier          = "mydb"
  engine              = "mysql"
  instance_class      = "db.m5.24xlarge"
  username            = "admin"
  password            = "Password123!"
  publicly_accessible = true
  storage_encrypted   = false
}