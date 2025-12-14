#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -subj "/CN=localhost" \
  -keyout server.key.pem -out server.crt.pem \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Wrote server.crt.pem and server.key.pem"
