#!/bin/bash

echo "=========================================="
echo "DevSecOps Policy Service Demo"
echo "=========================================="
echo ""

echo "Test 1: Safe Code "
echo "-----------------------------------"
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d @examples/test_safe.json | python3 -m json.tool
echo ""
echo ""

echo "Test 2: Public S3 Bucket"
echo "-----------------------------------"
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d @examples/test_unsafe.json | python3 -m json.tool
echo ""
echo ""

echo "Test 3: Hardcoded Secrets "
echo "-----------------------------------"
curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d @examples/test_secrets.json | python3 -m json.tool
echo ""

echo "=========================================="
echo "Demo Complete!"
echo "=========================================="
