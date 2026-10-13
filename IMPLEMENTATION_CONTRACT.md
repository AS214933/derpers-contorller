# Implementation contract (development coordination)

JSON uses snake_case. Shared DTOs are in internal/model/model.go; root owns that file.

## Controller

Go binary cmd/controller. Flags: controller --config /path/config.yaml <command>.
Serve command: serve. Configuration environment overrides: DATABASE_URL, MASTER_KEY (base64 32 bytes), CONTROLLER_URL, HTTP_ADDR, TLS_ADDR, TLS_CERT_FILE, TLS_KEY_FILE, NODE_CA_CERT_FILE, NODE_CA_KEY_FILE, HEADSCALE_ALLOWED_CIDRS (comma separated), OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_ADMIN_GROUPS.
HTTP_ADDR default :8080 for web behind reverse proxy; TLS_ADDR default :8443 is native Go TLS with VerifyClientCertIfGiven. Node APIs require an actual verified client certificate. Enrollment is anonymous HTTPS plus one-time token. E2E uses direct TLS :8443, same certificate trust. No auth bypass environment variable.

CLI:
- migrate
- network add --name hs --kind headscale --url https://headscale.e2e.test:8080/verify --ca-file /certs/ca.crt --approve (JSON Network)
- network set-status --id ID --status approved|disabled|rejected (JSON Network)
- node add --name e2e --hostname derp.e2e.test --ipv4 IP --https-port PORT --region-id 900 --region-code e2e --region-name E2E --stun=false --http=false --cert-file FILE --key-file FILE (JSON Node)
- node token --id ID (JSON {"token":"...","node_id":"..."})
- node publish --id ID (JSON Node)
- derpmap --format json|yaml (map of currently published nodes)
- audit list (JSON array)

## Agent

cmd/agent binary, environment: CONTROLLER_URL, ENROLLMENT_TOKEN, STATE_DIR=/var/lib/derpers-agent, CONFIG_DIR=/node, DOCKER_HOST=unix:///var/run/docker.sock, CONTROLLER_CA_FILE optional bootstrap trust, NODE_ID optional assertion, MANAGE_CONTAINERS=true, DERPER_CONTAINER, CADDY_CONTAINER. Enrollment private key stays local; persist client.crt/client.key/ca.crt + node ID. API:
- POST /api/v1/node-enroll -> EnrollmentResponse (TLS; request EnrollmentRequest)
- GET /node/v1/config -> NodeConfig
- GET /node/v1/tasks -> []Task
- POST /node/v1/report -> 204 (Report)
- POST /node/v1/renew -> EnrollmentResponse ({"csr":"..."})

derper -certmode manual -certdir /certs -hostname HOST -a :PORT -http-port -1 -stun BOOL -stun-port PORT -c /state/derper.key -verify-client-url http://caddy:9080/verify -verify-client-url-fail-open=false -verify-clients=false.
Caddy internal :9080 proxies /verify to CONTROLLER_URL/admission/v1/verify using agent client cert and controller CA. Optional :80 forwards /generate_204 to derper TLS with tls_server_name HOST and trusts certificate CA. Agent writes /node/certs/HOST.crt and .key, /node/Caddyfile, /node/derper-args.json. Mount /node/certs -> derper /certs; /node/derper-state -> /state; /node/Caddyfile via parent directory mount to Caddy; node identity readonly mount /agent-state for Caddy. Docker labels derpers.node_id and derpers.component; agent only operates its node containers. Official derper image entrypoint wrapper reads args JSON; do not hand-roll shell argument splitting.
Manage mode creates/reconciles derper and caddy containers via Docker API and shares the explicit DOCKER_NETWORK. Required HOST_CONFIG_DIR and HOST_STATE_DIR are absolute Linux host bind paths matching CONFIG_DIR and STATE_DIR. Production and final E2E both use MANAGE_CONTAINERS=true; false is an explicitly limited development mode for precreated containers. PUBLISH_NODE_PORTS defaults true (E2E false). POLL_INTERVAL and HEARTBEAT_INTERVAL default 15s; HEALTH_TIMEOUT defaults 30s. A separate heartbeat continues during image pulls and tasks. ALLOWED_IMAGE_PREFIXES optionally adds comma-separated allowed repository/registry prefixes; image changes require a sha256 digest and an existing trusted repository or configured prefix. Tasks restart|upgrade|logs use payload {"component":"derper|caddy","image":"...","tail":200}; upgrade also carries previous_image and target_revision and updates controller desired state atomically with the task. Agent loads tasks before configuration and applies upgrade/configuration in one recoverable transaction; failure reports the old applied revision. Only this node's ownership-labeled containers can be managed.

identity.json atomically persists the identity key/certificate pair; client.crt/client.key/ca.crt are repaired sidecars for Caddy. Enrollment ca_certificate is the identity issuer, not a replacement for controller server trust. Caddy server-ca.crt combines system roots, CONTROLLER_CA_FILE and NodeConfig.ca_pem. Managed Caddy CMD includes executable caddy (the standard image has no ENTRYPOINT). derper uses DERPER_ARGS_FILE=/node/derper-args.json, and /usr/local/bin/derper-entrypoint metrics reads loopback /debug/varz with correct TLS SNI and /certs/ca.crt. Persistent state.json records task outcomes/acknowledgements; configuration.pending.json journals multi-file updates for crash recovery. Secrets are mode 0600. Reports contain at most 64 selected DERP/Docker metrics and 100 task results within a 512 KiB result budget; successful reports persist acknowledgements without re-executing tasks.

## Web API

- GET /api/v1/me -> User (401 anonymous); GET /auth/login redirects; POST /auth/logout
- GET/POST /api/v1/networks -> []Network / Network
- GET/PUT/DELETE /api/v1/networks/{id}
- POST /api/v1/networks/{id}/test, /sync, /approve, /reject, /disable (admin for approval; own test/sync)
- Network save JSON: model Network + credentials object (client_id/client_secret for tailscale; ca_pem, bearer_token optional for headscale). Read never returns credentials.
- GET/POST /api/v1/nodes -> []Node / Node; PUT/DELETE /api/v1/nodes/{id}
- POST /api/v1/nodes/{id}/token -> {"token":...,"node_id":...}; /publish, /unpublish, /provision (DNS+ACME)
- GET /api/v1/nodes/{id}/deployment -> text YAML Compose (admin)
- GET /api/v1/nodes/{id}/tasks -> []Task; POST -> Task ({"type":"restart|upgrade|logs","payload":{...}})
- GET/POST /api/v1/dns-accounts -> []DNSAccount / DNSAccount; PUT/DELETE /api/v1/dns-accounts/{id}; POST .../{id}/test
- DNS save: DNSAccount + credentials map; cloudflare api_token; alidns access_key_id/access_key_secret; dnspod secret_id/secret_key.
- GET/PUT /api/v1/settings -> {"approval_mode":"manual|automatic"} (admin)
- GET /api/v1/audit -> []Audit (admin)
- GET /derpmap.json; GET /api/v1/derpmap?format=json|yaml -> text (authenticated, query only_custom=true toggles default regions)
- /healthz, /readyz, /metrics

Error JSON {"error":"safe human message"}. Mutation requires same-origin Origin if present. Frontend same-origin fetch, credentials include. Browser never receives secrets on read. No token in query strings.

Frontend web/dist copied into controller image /app/web, WEB_DIR env /app/web. No required Go embed asset directory. CLI image must include CA trust and tzdata; tests scripts only bootstrap CLI and TLS, no web authentication bypass.
