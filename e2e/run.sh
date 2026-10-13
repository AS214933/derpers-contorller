#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
set -a
source deploy/images.env
set +a
export IMAGE_TAG="${IMAGE_TAG:-test}"
export DERP_PORT="${DERP_PORT:-8443}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-derpers-e2e-${DERP_PORT}-${RANDOM}}"
[[ "$COMPOSE_PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]]
workspace="$(pwd -P)"
E2E_WORK="$(realpath -m "$workspace/.e2e/$COMPOSE_PROJECT_NAME")"
[[ "$E2E_WORK" == "$workspace/.e2e/"* ]]
MASTER_KEY="$(openssl rand -base64 32)"
export E2E_WORK MASTER_KEY
export ENROLLMENT_TOKEN="" NODE_ID=""
evidence="$(pwd)/artifacts/$COMPOSE_PROJECT_NAME"
mkdir -p "$E2E_WORK"/{certs,node,agent-state,headscale} "$evidence"
compose=(docker compose -p "$COMPOSE_PROJECT_NAME" -f e2e/compose.yaml)
derper="$COMPOSE_PROJECT_NAME-derper"
caddy="$COMPOSE_PROJECT_NAME-caddy"
stage=bootstrap
fault_pid=""
record() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$evidence/stages.log"; }
ctl() { "${compose[@]}" exec -T controller /usr/local/bin/controller "$@"; }
client() { "${compose[@]}" exec -T "$1" "${@:2}"; }
wait_for() {
  local seconds="$1"; shift
  local until=$((SECONDS+seconds))
  until "$@"; do
    if (( SECONDS >= until )); then record "TIMEOUT stage=$stage command=$*"; return 1; fi
    sleep 2
  done
}
collect() {
  set +e
  "${compose[@]}" --profile '*' logs --no-color --timestamps >"$evidence/services.log" 2>&1
  "${compose[@]}" --profile '*' ps -a --format json >"$evidence/compose-ps.json" 2>&1
  for component in "$derper" "$caddy"; do docker logs --timestamps "$component" >"$evidence/$component.log" 2>&1; done
  ctl audit list >"$evidence/audit.json" 2>/dev/null
  for name in client-a client-b; do
    client "$name" tailscale status --json >"$evidence/$name-status.json" 2>&1
    client "$name" tailscale debug derp-map >"$evidence/$name-derp-map.json" 2>&1
    client "$name" tailscale netcheck >"$evidence/$name-netcheck.txt" 2>&1
    client "$name" iptables -nvL OUTPUT >"$evidence/$name-iptables.txt" 2>&1
    client "$name" ip6tables -nvL OUTPUT >"$evidence/$name-ip6tables.txt" 2>&1
  done
  docker exec "$derper" /usr/local/bin/derper-entrypoint metrics >"$evidence/derper-metrics.txt" 2>&1
  docker image inspect "derpers-controller:$IMAGE_TAG" "derpers-agent:$IMAGE_TAG" "derpers-derper:$IMAGE_TAG" --format '{{.Id}} {{json .Config.Labels}}' >"$evidence/images.txt" 2>&1
  # Secrets are never collected; redact enrollment/preauth tokens from process logs.
  if [[ -n "$ENROLLMENT_TOKEN" ]]; then sed -i "s/$ENROLLMENT_TOKEN/[REDACTED]/g" "$evidence"/*.log; fi
  for token in "${key_a:-}" "${key_b:-}"; do if [[ -n "$token" ]]; then sed -i "s/$token/[REDACTED]/g" "$evidence"/*.log; fi; done
}
cleanup() {
  local result=$?
  record "TEST_RESULT exit=$result final_stage=$stage port=$DERP_PORT arch=$(uname -m)"
  if [[ -n "$fault_pid" ]]; then sudo nsenter -t "$fault_pid" -n iptables -D OUTPUT -d "$caddy_ip" -p tcp --dport 9080 -j REJECT 2>/dev/null || true; fi
  collect
  # Stop reconciliation before removing its managed components.
  "${compose[@]}" --profile agent stop -t 5 agent >/dev/null 2>&1 || true
  docker rm -f "$derper" "$caddy" >/dev/null 2>&1 || true
  "${compose[@]}" --profile '*' down -v --remove-orphans >/dev/null 2>&1 || true
  # This absolute path was constructed beneath this repository's .e2e directory.
  # Agent intentionally creates root-owned 0700 certificate/state directories.
  case "$E2E_WORK" in "$workspace/.e2e/"*)
    if ! sudo rm -rf -- "$E2E_WORK"; then result=1; record 'ERROR scoped E2E cleanup failed'; fi
    ;;
  *) result=1; record 'ERROR refusing cleanup outside the resolved workspace';;
  esac
  record "RESULT exit=$result final_stage=$stage port=$DERP_PORT arch=$(uname -m)"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    { printf '### Real DERP E2E: %s / %s\n\n' "$(uname -m)" "$DERP_PORT"; printf 'Result: **%s**. Final stage: %s. Images: %s.\n' "$result" "$stage" "$IMAGE_TAG"; cat "$evidence/stages.log"; } >>"$GITHUB_STEP_SUMMARY"
  fi
  exit "$result"
}
trap cleanup EXIT
for command in docker openssl jq timeout sudo nsenter; do command -v "$command" >/dev/null; done
docker compose version
test -c /dev/net/tun
if [[ "${E2E_SKIP_BUILD:-0}" != 1 ]]; then bash e2e/build-images.sh; fi
# Temporary root, server certificates and node identity issuer; never exported as artifacts.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$E2E_WORK/certs/ca.key" -out "$E2E_WORK/certs/ca.crt" -days 2 -subj /CN=derpers-e2e-ca >/dev/null 2>&1
for host in controller.e2e.test headscale.e2e.test derp.e2e.test; do
  openssl req -newkey rsa:2048 -nodes -keyout "$E2E_WORK/certs/$host.key" -out "$E2E_WORK/certs/$host.csr" -subj "/CN=$host" >/dev/null 2>&1
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host" >"$E2E_WORK/certs/$host.ext"
  openssl x509 -req -in "$E2E_WORK/certs/$host.csr" -CA "$E2E_WORK/certs/ca.crt" -CAkey "$E2E_WORK/certs/ca.key" -CAcreateserial -out "$E2E_WORK/certs/$host.crt" -days 2 -extfile "$E2E_WORK/certs/$host.ext" >/dev/null 2>&1
done
chmod -R a+rX "$E2E_WORK/certs"
"${compose[@]}" up -d postgres controller
controller_ready() { "${compose[@]}" exec -T controller curl -fsS http://127.0.0.1:8080/readyz >/dev/null 2>&1; }
wait_for 120 controller_ready
stage=node-bootstrap
node_json="$(ctl node add --name e2e --hostname derp.e2e.test --https-port "$DERP_PORT" --region-id 900 --region-code e2e --region-name E2E --stun=false --http=false --cert-file /certs/derp.e2e.test.crt --key-file /certs/derp.e2e.test.key --ca-file /certs/ca.crt --derper-image "derpers-derper:$IMAGE_TAG" --caddy-image "$CADDY_IMAGE")"
NODE_ID="$(jq -er .id <<<"$node_json")"
ENROLLMENT_TOKEN="$(ctl node token --id "$NODE_ID" | jq -er .token)"
export NODE_ID ENROLLMENT_TOKEN
"${compose[@]}" --profile agent up -d agent
node_healthy() { docker inspect -f '{{.State.Running}}' "$derper" 2>/dev/null | grep -qx true && docker inspect -f '{{.State.Running}}' "$caddy" 2>/dev/null | grep -qx true && ctl node publish --id "$NODE_ID" >"$evidence/published-node.json" 2>/dev/null; }
wait_for 150 node_healthy
ctl derpmap --format yaml >"$E2E_WORK/headscale/derp.yaml"
ctl derpmap --format json >"$evidence/expected-derp-map.json"
cat >"$E2E_WORK/headscale/config.yaml" <<'YAML'
server_url: https://headscale.e2e.test:8080
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 0.0.0.0:9090
noise:
  private_key_path: /var/lib/headscale/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: false
  urls: []
  paths: [/etc/headscale/derp.yaml]
  auto_update_enabled: false
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
tls_cert_path: /certs/headscale.e2e.test.crt
tls_key_path: /certs/headscale.e2e.test.key
dns:
  magic_dns: false
  override_local_dns: false
  base_domain: clients.e2e.test
  nameservers:
    global: []
unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: '0770'
disable_check_updates: true
logtail:
  enabled: false
log:
  level: info
  format: json
YAML
stage=headscale
"${compose[@]}" --profile headscale run --rm --no-deps headscale configtest
"${compose[@]}" --profile headscale up -d headscale
hs_ready() { "${compose[@]}" exec -T controller curl --cacert /certs/ca.crt --connect-timeout 2 --max-time 4 -fsS https://headscale.e2e.test:8080/health >"$evidence/headscale-health.txt" 2>&1; }
wait_for 90 hs_ready
"${compose[@]}" exec -T headscale headscale users create e2e >/dev/null
user_id="$("${compose[@]}" exec -T headscale headscale users list --output json | jq -er '.[] | select(.name=="e2e") | .id')"
key_a="$("${compose[@]}" exec -T headscale headscale preauthkeys create --user "$user_id" --expiration 1h --output json | jq -er .key)"
key_b="$("${compose[@]}" exec -T headscale headscale preauthkeys create --user "$user_id" --expiration 1h --output json | jq -er .key)"
network_id="$(ctl network add --name e2e-headscale --kind headscale --url https://headscale.e2e.test:8080/verify --ca-file /certs/ca.crt --approve | jq -er .id)"
stage=clients
"${compose[@]}" --profile clients up -d client-a client-b
daemon_ready() { client "$1" tailscale status --json >/dev/null 2>&1; }
wait_for 60 daemon_ready client-a
wait_for 60 daemon_ready client-b
client client-a tailscale up --login-server=https://headscale.e2e.test:8080 --auth-key="$key_a" --hostname=client-a --accept-dns=false
client client-b tailscale up --login-server=https://headscale.e2e.test:8080 --auth-key="$key_b" --hostname=client-b --accept-dns=false
ip_a="$(client client-a tailscale ip -4)"; ip_b="$(client client-b tailscale ip -4)"
peer_present() { client "$1" tailscale status --json | jq -e --arg ip "$2" '(.BackendState=="Running") and any(.Peer[]?; any(.TailscaleIPs[]?; .==$ip))' >/dev/null; }
wait_for 60 peer_present client-a "$ip_b"
wait_for 60 peer_present client-b "$ip_a"
check_map() { client "$1" tailscale debug derp-map | tee "$evidence/$1-map-$stage.json" | jq -e --argjson port "$DERP_PORT" '(.Regions|length)==1 and .Regions["900"].RegionCode=="e2e" and (.Regions["900"].Nodes|length)==1 and .Regions["900"].Nodes[0].HostName=="derp.e2e.test" and .Regions["900"].Nodes[0].DERPPort==$port' >/dev/null; }
check_map client-a; check_map client-b
baseline() {
  local name target output count
  peer_present client-a "$ip_b" || return 1
  peer_present client-b "$ip_a" || return 1
  for name in client-a client-b; do
    if [[ "$name" == client-a ]]; then target="$ip_b"; else target="$ip_a"; fi
    output="$(timeout 45 "${compose[@]}" exec -T "$name" tailscale ping --timeout=5s --until-direct=false --c=5 "$target")" || return 1
    printf '%s\n' "$output" >"$evidence/$stage-$name-disco.txt"
    count="$(grep -c '^pong ' <<<"$output" || true)"; [[ "$count" -ge 3 ]] || return 1
    if grep '^pong ' <<<"$output" | grep -v ' via DERP(e2e) '; then return 1; fi
    timeout 20 "${compose[@]}" exec -T "$name" tailscale ping --tsmp --timeout=5s "$target" >"$evidence/$stage-$name-tsmp.txt" || return 1
    timeout 15 "${compose[@]}" exec -T "$name" ping -c 3 -W 3 "$target" >"$evidence/$stage-$name-icmp.txt" || return 1
    client "$name" iptables -C OUTPUT -o eth0 -p udp -j REJECT || return 1
    client "$name" ip6tables -C OUTPUT -o eth0 -p udp -j REJECT || return 1
  done
  record "PASS stage=$stage bidirectional DERP DISCO + TSMP + TUN/ICMP"
}
stage=positive
baseline
ctl audit list >"$evidence/positive-audit.json"
pub_a="$(client client-a tailscale status --json | jq -er .Self.PublicKey)"
pub_b="$(client client-b tailscale status --json | jq -er .Self.PublicKey)"
jq -e --arg a "$pub_a" --arg b "$pub_b" --arg network "$network_id" 'any(.[]; .node_public==$a and .allow==true and .network_id==$network) and any(.[]; .node_public==$b and .allow==true and .network_id==$network)' "$evidence/positive-audit.json" >/dev/null
docker exec "$derper" /usr/local/bin/derper-entrypoint metrics >"$evidence/positive-metrics.txt"
grep -Eq 'derp_(packets_sent|bytes_sent) [1-9][0-9]*' "$evidence/positive-metrics.txt"
stage="unknown-key"
client client-a derp-probe --url "https://derp.e2e.test:$DERP_PORT/derp" --ca /certs/ca.crt >"$evidence/unknown-probe.jsonl"
unknown="$(head -n1 "$evidence/unknown-probe.jsonl" | jq -er .node_public)"
tail -n1 "$evidence/unknown-probe.jsonl" | jq -e '.phase=="closed"' >/dev/null
ctl audit list | jq -e --arg key "$unknown" 'any(.[]; .node_public==$key and .allow==false)' >/dev/null
record "PASS stage=$stage real DERP protocol denied before ServerInfo"
baseline
tls_up() { client client-a curl --cacert /certs/ca.crt -fsS "https://derp.e2e.test:$DERP_PORT/derp/probe" >/dev/null; }
negative() {
  tls_up
  peer_present client-a "$ip_b"; peer_present client-b "$ip_a"
  check_map client-a; check_map client-b
  local name target output code
  for name in client-a client-b; do
    if [[ "$name" == client-a ]]; then target="$ip_b"; else target="$ip_a"; fi
    set +e
    output="$(timeout 25 "${compose[@]}" exec -T "$name" tailscale ping --timeout=3s --until-direct=false --c=3 "$target" 2>&1)"; code=$?
    set -e
    printf '%s\n' "$output" >"$evidence/$stage-$name-denied.txt"
    [[ "$code" -ne 0 && "$code" -ne 124 && "$code" -ne 127 ]]
    if grep -q '^pong ' <<<"$output"; then return 1; fi
    grep -Eq 'timed out|no reply' <<<"$output"
    peer_present "$name" "$target"
  done
  record "PASS stage=$stage TLS and peers healthy, zero DERP pongs"
}
stage=source-disabled
ctl network set-status --id "$network_id" --status disabled >/dev/null
docker restart "$derper" >/dev/null
wait_for 30 tls_up
negative
ctl audit list | jq -e --arg key "$pub_a" 'any(.[]; .node_public==$key and .allow==false)' >/dev/null
ctl network set-status --id "$network_id" --status approved >/dev/null
stage=source-restored
wait_for 90 baseline
stage=controller-unreachable
fault_started="$(date -u +%FT%TZ)"
"${compose[@]}" stop controller >/dev/null
docker restart "$derper" >/dev/null
wait_for 30 tls_up
negative
docker logs --since "$fault_started" "$derper" >"$evidence/controller-unreachable-derper.log" 2>&1
grep -Eq 'rejected:.*admission controller:.*502|rejected:.*admission controller:.*503' "$evidence/controller-unreachable-derper.log"
"${compose[@]}" start controller >/dev/null
wait_for 90 controller_ready
stage=controller-restored
wait_for 90 baseline
stage=verify-transport-failure
# Caddy's 502 would reject even with fail-open=true. This forces Do() itself to fail.
fault_started="$(date -u +%FT%TZ)"
fault_pid="$(docker inspect -f '{{.State.Pid}}' "$derper")"
caddy_ip="$(docker inspect "$caddy" | jq -er '.[0].NetworkSettings.Networks[] | .IPAddress')"
sudo nsenter -t "$fault_pid" -n iptables -I OUTPUT 1 -d "$caddy_ip" -p tcp --dport 9080 -j REJECT
client client-a tailscale debug break-derp-conns
client client-b tailscale debug break-derp-conns
negative
docker logs --since "$fault_started" "$derper" >"$evidence/verify-transport-failure-derper.log" 2>&1
grep -Eq 'rejected:.*Post .*http://caddy:9080/verify.*(refused|unreachable|timeout)' "$evidence/verify-transport-failure-derper.log"
sudo nsenter -t "$fault_pid" -n iptables -D OUTPUT -d "$caddy_ip" -p tcp --dport 9080 -j REJECT
fault_pid=""
stage=transport-restored
wait_for 90 baseline
stage=internal-isolation
status="$(client client-a curl --cacert /certs/ca.crt -s -o /dev/null -w '%{http_code}' "https://derp.e2e.test:$DERP_PORT/debug/vars")"
[[ "$status" == 403 ]]
docker inspect "$derper" "$caddy" | jq -e 'all(.[]; [.HostConfig.PortBindings | keys[]?] | all(.=="443/tcp" or .=="8443/tcp" or .=="3478/udp" or .=="80/tcp"))' >/dev/null
record "PASS stage=$stage debug protected and no internal port published"
stage=complete
record "PASS all stages"
