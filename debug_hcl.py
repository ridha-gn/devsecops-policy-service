"""Debug script to test the FIXED parser output."""
import json
from engine.parser import TerraformParser

parser = TerraformParser()

code = '''provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI"
}

resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "public-read"
}

resource "aws_db_instance" "db" {
  identifier          = "mydb"
  engine              = "mysql"
  publicly_accessible = true
  storage_encrypted   = false
  password            = "Password123!"
}
'''

result = parser.parse(code)
print("=== PARSED (after _strip_quotes) ===")
print(json.dumps(result, indent=2, default=str))

resources = parser.extract_resources(result)
print("\n=== EXTRACTED RESOURCES ===")
for r in resources:
    print(f"  Type: {r['type']}, Name: {r['name']}")
    print(f"    Attributes: {json.dumps(r['attributes'], indent=6, default=str)}")

providers = parser.extract_providers(result)
print("\n=== EXTRACTED PROVIDERS ===")
for p in providers:
    print(f"  Provider: {p['name']}")
    print(f"    Config: {json.dumps(p['config'], indent=6, default=str)}")

# Test: does 'acl' == 'public-read'?
for r in resources:
    acl = r['attributes'].get('acl', '')
    print(f"\n  [{r['type']}] acl value = '{acl}' (matches 'public-read'? {acl == 'public-read'})")
    password = r['attributes'].get('password', '')
    if password:
        print(f"  [{r['type']}] password value = '{password}'")
