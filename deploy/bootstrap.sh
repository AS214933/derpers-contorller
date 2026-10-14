#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
umask 077
[[ ! -e .env ]] || { echo 'deploy/.env already exists; refusing to replace secrets' >&2; exit 1; }
mkdir -p secrets
[[ ! -e secrets/node-ca.key ]] || { echo 'node CA already exists; refusing to replace identity issuer' >&2; exit 1; }
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -keyout secrets/node-ca.key -out secrets/node-ca.crt -subj /CN=derpers-node-identity-ca
password="$(openssl rand -hex 24)"
master="$(openssl rand -base64 32)"
grafana_password="$(openssl rand -hex 24)"
metrics_token="$(openssl rand -hex 32)"
printf '%s' "$metrics_token" >secrets/metrics-token
sed -e "s/^POSTGRES_PASSWORD=$/POSTGRES_PASSWORD=$password/" -e "s|^MASTER_KEY=$|MASTER_KEY=$master|" -e "s/^GRAFANA_ADMIN_PASSWORD=$/GRAFANA_ADMIN_PASSWORD=$grafana_password/" -e "s/^METRICS_TOKEN=$/METRICS_TOKEN=$metrics_token/" .env.example >.env
printf '\nCreated deploy/.env, database secrets and node identity CA. Configure OIDC and public HTTPS URLs.\n'
printf 'Set the public host in nginx-origin.conf and restrict the HTTP origin to EdgeOne before exposing it.\n'
