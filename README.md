# SROIAAA Phase One Prototype

Secure Read-Only Infrastructure API for AI and Automation, or SROIAAA,
is a Phase One prototype for a safe, read-only Linux endpoint agent.
The long-term target is a native Linux service managed by `systemd`;
Docker is used here only as a controlled development harness.

This prototype intentionally does **not** expose arbitrary shell
execution. It offers a small bounded operation API and records
structured audit events so we can derive a finite operation catalog
empirically.

## Phase One scope

The initial operation set is deliberately narrow:

- `host.info`
- `filesystem.list`
- `filesystem.stat`
- `filesystem.read`
- `filesystem.tail`
- `process.list`
- `capabilities.describe`

Core constraints:

- absolute paths only
- allowlisted roots only
- symlink-aware root enforcement
- bounded reads, tails, and fan-out
- bounded HTTP request bodies and server deadlines
- read-only API surface
- structured JSON-line audit log

## Layout

```text
cmd/sroiaaa-agent/         main program
cmd/sroiaaa-broker-plan/   broker-v0 route planning CLI
internal/agent/            API, execution, validation, audit logic
internal/broker/           deterministic policy and routing kernel
configs/                   example broker policy
testdata/workspace/        sample files mounted into the container
testdata/varlog/           sample log files mounted into the container
```

## Quick start

After cloning, define the repository root once:

```bash
git clone https://github.com/bindatype/SROIAAA.git
cd SROIAAA
SRO_ROOT="${SRO_ROOT:-$PWD}"
export SROIAAA_AUTH_TOKEN="${SROIAAA_AUTH_TOKEN:-dev-sroiaaa-token}"
```

### Local

```bash
cd "$SRO_ROOT"
go test ./...
go run ./cmd/sroiaaa-agent
```

The native server listens on `127.0.0.1:8080` by default and requires a
bearer token on all API routes except `/healthz`. Remote exposure must be
enabled explicitly and should be constrained by host firewall policy or a
TLS-authenticated broker or reverse proxy.

To override the host-run port explicitly:

```bash
SROIAAA_BIND_ADDR=127.0.0.1:18081 go run ./cmd/sroiaaa-agent
```

To listen on all IPv6 interfaces, including IPv4 where the host permits
dual-stack sockets:

```bash
SROIAAA_BIND_ADDR='[::]:18081' go run ./cmd/sroiaaa-agent
```

### Cross-architecture builds

The agent is a pure-Go Linux binary, so the repository supports both
`linux/amd64` and `linux/arm64` builds.

```bash
cd "$SRO_ROOT"
make build-linux-all
```

This writes:

- `dist/sroiaaa-agent-linux-amd64`
- `dist/sroiaaa-agent-linux-arm64`

### Docker harness

```bash
cd "$SRO_ROOT"
docker compose up --build
```

The Docker harness publishes the container on host loopback port `18080`
so it does not collide with a direct local `go run` on port `8080` and is
not remotely reachable by default.

The compose harness:

- runs the agent as a non-root user
- mounts sample data read-only at `/workspace` and `/var/log/sroiaaa`
- uses a read-only container filesystem
- drops Linux capabilities
- writes audit logs to `./runtime/audit.log`

The Dockerfile also honors Docker's target platform arguments, so it can
participate in multi-architecture builds such as `linux/amd64` and
`linux/arm64` when used with a suitable Docker builder.

### Harness fitness

To survey whether the harness contains the read-only operator tools we
actually want to rely on, run:

```bash
cd "$SRO_ROOT"
make fitness
```

This writes a markdown report to `runtime/harness-fitness.md` with four
tiers:

- core read-only tools that should generally be present
- recommended network or operator probes
- optional specialized network diagnostics
- contextual host or HPC tools that may be absent in a minimal harness

## Example requests

Health:

```bash
curl -fsS http://127.0.0.1:18080/healthz | jq .
```

Capabilities:

```bash
curl -fsS \
  -H "Authorization: Bearer $SROIAAA_AUTH_TOKEN" \
  http://127.0.0.1:18080/v1/capabilities | jq .
```

Host info:

```bash
curl -fsS -X POST http://127.0.0.1:18080/v1/operations \
  -H "Authorization: Bearer $SROIAAA_AUTH_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "operation": "host.info"
  }' | jq .
```

List a directory:

```bash
curl -fsS -X POST http://127.0.0.1:18080/v1/operations \
  -H "Authorization: Bearer $SROIAAA_AUTH_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "operation": "filesystem.list",
    "target": {"path": "/workspace"},
    "params": {"max_entries": 32}
  }' | jq .
```

Tail a log:

```bash
curl -fsS -X POST http://127.0.0.1:18080/v1/operations \
  -H "Authorization: Bearer $SROIAAA_AUTH_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "operation": "filesystem.tail",
    "target": {"path": "/var/log/sroiaaa/system.log"},
    "params": {"max_bytes": 2048}
  }' | jq .
```

## Configuration

Configuration is environment-driven:

- `SROIAAA_BIND_ADDR` default `127.0.0.1:8080`
- `SROIAAA_AUTH_TOKEN` required single bearer token
- `SROIAAA_AUTH_TOKENS` optional comma-separated additional valid tokens for rotation
- `SROIAAA_ALLOWED_ROOTS` default `/workspace,/tmp,/var/log/sroiaaa`
- `SROIAAA_PROC_ROOT` default `/proc`
- `SROIAAA_MAX_REQUEST_BYTES` default `65536`
- `SROIAAA_MAX_READ_BYTES` default `65536`
- `SROIAAA_MAX_TAIL_BYTES` default `65536`
- `SROIAAA_MAX_LIST_ENTRIES` default `256`
- `SROIAAA_MAX_PROCESS_ENTRIES` default `256`
- `SROIAAA_AUDIT_PATH` default `runtime/audit.log`
- `SROIAAA_READ_HEADER_TIMEOUT` default `5s`
- `SROIAAA_READ_TIMEOUT` default `15s`
- `SROIAAA_WRITE_TIMEOUT` default `30s`
- `SROIAAA_IDLE_TIMEOUT` default `60s`

## Broker routing experiment

Broker v0 begins as a planning-only executable. It does not listen on a
network port, hold credentials, or call live data sources yet. Its job is
to turn a small structured intent into a deterministic route plan.

| Intent | Route |
|---|---|
| `fleet.inventory` | Wazuh API `agents.list` |
| `agent.status` | Wazuh API `agents.status` |
| `monitoring.problems` | Zabbix API `trigger.get` |
| `live.evidence` | A fixed SROIAAA operation from broker policy |

MindRouter is used before routing to propose the structured intent and
after evidence collection to synthesize an answer. It is not permitted to
choose connector URLs, API methods, SROIAAA operations, or filesystem
paths.

The broker policy is versioned JSON. `live_hosts` is an authorization
scope for direct SROIAAA access, not a replacement fleet inventory;
Wazuh remains the intended inventory source. Resource aliases map to
fixed operations, canonical paths, and limits. The current broker kernel
permits only bounded `filesystem.list`, `filesystem.stat`,
`filesystem.read`, and `filesystem.tail` routes.

Generate a route plan against the safe harness example:

```bash
printf '%s\n' \
  '{"intent":"live.evidence","host":"docker-harness","resource":"system-log"}' \
  | go run ./cmd/sroiaaa-broker-plan \
      -policy ./configs/broker-policy.example.json
```

Requests containing unrecognized fields are rejected. In particular,
adding a model-selected `path`, `operation`, or endpoint to the request
does not expand broker authority.

## Empirical catalog workflow

Phase One is also a research exercise. For each admin or diagnostic task
we perform in the Docker harness, we should record:

- the task
- the operations actually used
- missing fields or limits that blocked progress
- candidate primitive splits or merges

That dataset should drive the finite operation catalog instead of
guesswork.
