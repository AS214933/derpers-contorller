#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
umask 077
[[ ! -e .env ]] || { echo 'deploy/.env already exists; refusing to replace secrets' >&2; exit 1; }
mkdir -p secrets
[[ ! -e secrets/node-ca.key ]] || { echo 'node CA already exists; refusing to replace identity issuer' >&2; exit 1; }
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -keyout secrets/node-ca.key -out secrets/node-ca.crt -subj /CN=derpers-node-identity-ca
openssl req -x509 -newkey rsa:3072 -nodes -days 30 -keyout secrets/server.key -out secrets/server.crt -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -addext extendedKeyUsage=serverAuth
password="$(openssl rand -hex 24)"
master="$(openssl rand -base64 32)"
grafana_password="$(openssl rand -hex 24)"
sed -e "s/^POSTGRES_PASSWORD=$/POSTGRES_PASSWORD=$password/" -e "s|^MASTER_KEY=$|MASTER_KEY=$master|" -e "s/^GRAFANA_ADMIN_PASSWORD=$/GRAFANA_ADMIN_PASSWORD=$grafana_password/" .env.example >.env
printf '\nCreated deploy/.env and local TLS/identity certificates. Configure OIDC before opening the portal.\n'
printf 'For production replace secrets/server.crt + server.key with a valid certificate for CONTROLLER_URL.\n'
