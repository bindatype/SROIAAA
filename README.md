# SROIAAA Phase One Prototype

SROIAAA is a Phase One prototype for a safe, read-only Linux endpoint
agent. The long-term target is a native Linux service managed by
`systemd`; Docker is used here only as a controlled development harness.

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
- read-only API surface
- structured JSON-line audit log

## Layout

```text
cmd/sroiaaa-agent/         main program
internal/agent/            API, execution, validation, audit logic
testdata/workspace/        sample files mounted into the container
testdata/varlog/           sample log files mounted into the container
```

## Quick start

After cloning, define the repository root once:

```bash
git clone https://github.com/bindatype/SROIAAA.git
cd SROIAAA
SRO_ROOT="${SRO_ROOT:-$PWD}"
```

### Local

```bash
cd "$SRO_ROOT"
go test ./...
go run ./cmd/sroiaaa-agent
```

The server listens on `:8080` by default.

To override the host-run port explicitly:

```bash
SROIAAA_BIND_ADDR=:18081 go run ./cmd/sroiaaa-agent
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

The Docker harness publishes the container on host port `18080` so it
does not collide with a direct local `go run` on `:8080`.

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
curl -fsS http://127.0.0.1:18080/v1/capabilities | jq .
```

Host info:

```bash
curl -fsS -X POST http://127.0.0.1:18080/v1/operations \
  -H 'content-type: application/json' \
  -d '{
    "operation": "host.info"
  }' | jq .
```

List a directory:

```bash
curl -fsS -X POST http://127.0.0.1:18080/v1/operations \
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
  -H 'content-type: application/json' \
  -d '{
    "operation": "filesystem.tail",
    "target": {"path": "/var/log/sroiaaa/system.log"},
    "params": {"max_bytes": 2048}
  }' | jq .
```

## Configuration

Configuration is environment-driven:

- `SROIAAA_BIND_ADDR` default `:8080`
- `SROIAAA_ALLOWED_ROOTS` default `/workspace,/tmp,/var/log/sroiaaa`
- `SROIAAA_PROC_ROOT` default `/proc`
- `SROIAAA_MAX_READ_BYTES` default `65536`
- `SROIAAA_MAX_TAIL_BYTES` default `65536`
- `SROIAAA_MAX_LIST_ENTRIES` default `256`
- `SROIAAA_MAX_PROCESS_ENTRIES` default `256`
- `SROIAAA_AUDIT_PATH` default `runtime/audit.log`

## Empirical catalog workflow

Phase One is also a research exercise. For each admin or diagnostic task
we perform in the Docker harness, we should record:

- the task
- the operations actually used
- missing fields or limits that blocked progress
- candidate primitive splits or merges

That dataset should drive the finite operation catalog instead of
guesswork.
