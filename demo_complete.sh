#!/bin/bash

echo "========================================================"
echo "  DevSecOps Policy Service - Complete Demo"
echo "========================================================"
echo ""

echo "1️⃣  Service Health Check"
echo "----------------------------"
curl -s http://localhost:8000 | python3 -m json.tool
echo ""
echo ""

echo "2️⃣  Terraform - Safe Code (ALLOW)"
echo "----------------------------"
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code_type": "terraform",
    "content": "resource \"aws_s3_bucket\" \"safe\" {\n  bucket = \"my-bucket\"\n  acl = \"private\"\n  server_side_encryption_configuration {\n    rule {\n      apply_server_side_encryption_by_default {\n        sse_algorithm = \"AES256\"\n      }\n    }\n  }\n  tags = {\n    Environment = \"prod\"\n    Owner = \"team\"\n    CostCenter = \"engineering\"\n  }\n}"
  }' | python3 -m json.tool
echo ""
echo ""

echo "3️⃣  Terraform - Multiple Violations (BLOCK)"
echo "----------------------------"
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code_type": "terraform",
    "content": "resource \"aws_s3_bucket\" \"bad\" {\n  bucket = \"my-bucket\"\n  acl = \"public-read\"\n}\n\nresource \"aws_db_instance\" \"db\" {\n  identifier = \"mydb\"\n  storage_encrypted = false\n  publicly_accessible = true\n}"
  }' | python3 -m json.tool
echo ""
echo ""

echo "4️⃣  Hardcoded Secrets (CRITICAL)"
echo "----------------------------"
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code_type": "terraform",
    "content": "provider \"aws\" {\n  access_key = \"AKIAIOSFODNN7EXAMPLE\"\n  secret_key = \"mysecretkey123\"\n}"
  }' | python3 -m json.tool
echo ""
echo ""

echo "5️⃣  Dockerfile - Root User (MEDIUM)"
echo "----------------------------"
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code_type": "dockerfile",
    "content": "FROM ubuntu:20.04\nRUN apt-get update\nCMD [\"/bin/bash\"]"
  }' | python3 -m json.tool
echo ""
echo ""

echo "6️⃣  Metrics Dashboard"
echo "----------------------------"
curl -s http://localhost:8000/metrics | python3 -m json.tool
echo ""
echo ""

echo "========================================================"
echo "  ✅ Demo Complete!"
echo "========================================================"
echo ""
echo "📊 Summary:"
echo "  - 5 test cases executed"
echo "  - Multiple violation types demonstrated"
echo "  - Metrics collected and displayed"
echo ""
echo "🌐 Interactive API docs available at:"
echo "  http://localhost:8000/docs"
echo ""