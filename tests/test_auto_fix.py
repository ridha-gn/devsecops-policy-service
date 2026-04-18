"""
Tests for new features: Auto-Fix, Prometheus metrics, PDF reports.
"""

import pytest
from engine.auto_fix import AutoFixer


fixer = AutoFixer()


# ──────────────────────────────────────────────────────────────────────
#  AUTO-FIX: TERRAFORM
# ──────────────────────────────────────────────────────────────────────

class TestTerraformFixes:

    def test_fix_public_s3_bucket(self):
        code = '''resource "aws_s3_bucket" "bad" {
  bucket = "my-bucket"
  acl    = "public-read"
}'''
        result = fixer.fix("terraform", code)
        assert result.has_fixes
        assert 'acl    = "private"' in result.fixed_code
        assert any(f.rule_id == "PUBLIC_S3_BUCKET" for f in result.fixes_applied)

    def test_fix_public_read_write(self):
        code = 'acl = "public-read-write"'
        result = fixer.fix("terraform", code)
        assert 'acl = "private"' in result.fixed_code

    def test_fix_public_database(self):
        code = '''resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
}'''
        result = fixer.fix("terraform", code)
        assert "publicly_accessible = false" in result.fixed_code
        assert "storage_encrypted   = true" in result.fixed_code

    def test_fix_hardcoded_aws_key(self):
        code = '''provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "mysecretkey123"
}'''
        result = fixer.fix("terraform", code)
        assert "AKIAIOSFODNN7EXAMPLE" not in result.fixed_code
        assert "${var.aws_access_key}" in result.fixed_code
        assert "${var.aws_secret_key}" in result.fixed_code

    def test_fix_hardcoded_password(self):
        code = 'password = "supersecret123"'
        result = fixer.fix("terraform", code)
        assert "supersecret123" not in result.fixed_code
        assert "${var.db_password}" in result.fixed_code

    def test_fix_security_group_open(self):
        code = 'cidr_blocks = ["0.0.0.0/0"]'
        result = fixer.fix("terraform", code)
        assert "10.0.0.0/8" in result.fixed_code

    def test_fix_ec2_public_ip(self):
        code = "associate_public_ip_address = true"
        result = fixer.fix("terraform", code)
        assert "associate_public_ip_address = false" in result.fixed_code

    def test_fix_deletion_protection(self):
        code = "deletion_protection = false"
        result = fixer.fix("terraform", code)
        assert "deletion_protection = true" in result.fixed_code

    def test_no_fixes_needed(self):
        code = '''resource "aws_s3_bucket" "good" {
  bucket = "my-bucket"
  acl    = "private"
}'''
        result = fixer.fix("terraform", code)
        assert result.total_fixes == 0
        assert result.fixed_code == code

    def test_multiple_fixes_combined(self):
        code = '''resource "aws_s3_bucket" "bad" {
  acl = "public-read"
}
resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
}'''
        result = fixer.fix("terraform", code)
        assert result.total_fixes >= 3
        assert 'acl = "private"' in result.fixed_code
        assert "publicly_accessible = false" in result.fixed_code
        assert "storage_encrypted   = true" in result.fixed_code


# ──────────────────────────────────────────────────────────────────────
#  AUTO-FIX: DOCKERFILE
# ──────────────────────────────────────────────────────────────────────

class TestDockerfileFixes:

    def test_fix_root_user(self):
        code = '''FROM python:3.10
RUN pip install flask
CMD ["python", "app.py"]'''
        result = fixer.fix("dockerfile", code)
        assert "USER appuser" in result.fixed_code
        assert any(f.rule_id == "DOCKER_ROOT_USER" for f in result.fixes_applied)

    def test_fix_latest_tag(self):
        code = "FROM ubuntu:latest\nRUN echo hello"
        result = fixer.fix("dockerfile", code)
        assert ":latest" not in result.fixed_code
        assert "<PIN_VERSION>" in result.fixed_code

    def test_fix_healthcheck_missing(self):
        code = '''FROM python:3.10
RUN pip install flask
CMD ["python", "app.py"]'''
        result = fixer.fix("dockerfile", code)
        assert "HEALTHCHECK" in result.fixed_code

    def test_already_has_user(self):
        code = '''FROM python:3.10
USER appuser
CMD ["python", "app.py"]'''
        result = fixer.fix("dockerfile", code)
        # Should NOT add another USER instruction
        assert result.fixed_code.count("USER appuser") == 1


# ──────────────────────────────────────────────────────────────────────
#  AUTO-FIX: KUBERNETES
# ──────────────────────────────────────────────────────────────────────

class TestKubernetesFixes:

    def test_fix_privileged(self):
        code = '''securityContext:
  privileged: true'''
        result = fixer.fix("yaml", code)
        assert "privileged: false" in result.fixed_code

    def test_fix_host_network(self):
        code = "hostNetwork: true"
        result = fixer.fix("yaml", code)
        assert "hostNetwork: false" in result.fixed_code

    def test_fix_privilege_escalation(self):
        code = "allowPrivilegeEscalation: true"
        result = fixer.fix("yaml", code)
        assert "allowPrivilegeEscalation: false" in result.fixed_code

    def test_fix_run_as_root(self):
        code = "runAsUser: 0\n"
        result = fixer.fix("yaml", code)
        assert "runAsUser: 1000" in result.fixed_code


# ──────────────────────────────────────────────────────────────────────
#  DIFF GENERATION
# ──────────────────────────────────────────────────────────────────────

class TestDiffGeneration:

    def test_diff_output(self):
        original = 'acl = "public-read"'
        fixed = 'acl = "private"'
        diff = fixer.generate_diff(original, fixed)
        assert '-acl = "public-read"' in diff
        assert '+acl = "private"' in diff

    def test_diff_no_changes(self):
        code = 'acl = "private"'
        diff = fixer.generate_diff(code, code)
        assert diff == ""


# ──────────────────────────────────────────────────────────────────────
#  UNSUPPORTED CODE TYPE
# ──────────────────────────────────────────────────────────────────────

class TestUnsupportedType:

    def test_unsupported_returns_unchanged(self):
        result = fixer.fix("unknown", "some code")
        assert result.total_fixes == 0
        assert result.fixed_code == "some code"
