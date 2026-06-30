#!/usr/bin/env bash
set -euo pipefail

IRIS_VERSION="${IRIS_VERSION:-v2.4.20}"
BASE_DIR="${BASE_DIR:-external}"
mkdir -p "$BASE_DIR"

if [ ! -d "$BASE_DIR/iris-web/.git" ]; then
  git clone https://github.com/dfir-iris/iris-web.git "$BASE_DIR/iris-web"
fi

cd "$BASE_DIR/iris-web"
git fetch --tags
git checkout "$IRIS_VERSION"
cp -n .env.model .env

docker compose pull
docker compose up -d

echo "DFIR-IRIS upstream started. Open https://localhost or the configured INTERFACE_HTTPS_PORT."
echo "Set IRIS_URL and IRIS_API_KEY in SATRIA .env after creating a service account/API key."
