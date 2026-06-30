#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${SATRIA_BASE_URL:-http://localhost:8090}"

asset_json=$(curl -s -X POST "$BASE_URL/api/assets" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Demo Nginx Image","asset_type":"container_image","target":"nginx:latest","environment":"development","criticality":"medium","owner":"Security Lab","technical_pic":"DevSecOps"}')

echo "$asset_json"
asset_id=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<< "$asset_json")

curl -s -X POST "$BASE_URL/api/scans" \
  -H 'Content-Type: application/json' \
  -d "{\"asset_id\":${asset_id},\"profile\":\"full_container\"}"
echo
