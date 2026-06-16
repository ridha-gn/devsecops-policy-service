import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200

    assert "html" in response.headers.get("content-type", "").lower()


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_analyze_safe_code():
    request_data = {
        "code_type": "terraform",
        "content": 'resource "aws_s3_bucket" "safe" { acl = "private" }',
        "block_threshold": "CRITICAL",
    }
    response = client.post("/analyze", json=request_data)
    assert response.status_code == 200
    data = response.json()

    assert data["decision"] == "ALLOW"


def test_analyze_public_s3():
    request_data = {
        "code_type": "terraform",
        "content": """resource "aws_s3_bucket" "bad" {
  bucket = "my-bucket"
  acl    = "public-read"
}""",
    }
    response = client.post("/analyze", json=request_data)
    assert response.status_code == 200
    data = response.json()

    assert len(data["violations"]) > 0
    assert any(v["rule"] == "PUBLIC_S3_BUCKET" for v in data["violations"])


def test_analyze_hardcoded_secret():
    request_data = {
        "code_type": "terraform",
        "content": """resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  access_key    = "AKIAIOSFODNN7EXAMPLE"
}""",
    }
    response = client.post("/analyze", json=request_data)
    assert response.status_code == 200
    data = response.json()
    violations = data["violations"]
    assert any(v["rule"] == "HARDCODED_SECRET" for v in violations)


def test_invalid_code_type():
    request_data = {"code_type": "invalid_type", "content": "some content"}
    response = client.post("/analyze", json=request_data)
    assert response.status_code == 422


def test_fix_endpoint():
    request_data = {
        "code_type": "terraform",
        "content": """resource "aws_s3_bucket" "bad" {
  acl = "public-read"
}""",
    }
    response = client.post("/fix", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert data["total_fixes"] > 0
    assert '"private"' in data["fixed_code"]


def test_fix_no_changes_needed():
    request_data = {
        "code_type": "terraform",
        "content": 'resource "aws_s3_bucket" "good" { acl = "private" }',
    }
    response = client.post("/fix", json=request_data)
    assert response.status_code == 200
    data = response.json()
    assert data["total_fixes"] == 0


def test_prometheus_metrics():
    response = client.get("/metrics/prometheus")
    assert response.status_code == 200
    text = response.text
    assert "devsecops_scans_total" in text
    assert "devsecops_blocks_total" in text


def test_metrics_json():
    response = client.get("/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_requests" in data


def test_history():
    response = client.get("/history")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
