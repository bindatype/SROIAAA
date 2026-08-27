# Onboarding a contributor

For a second developer joining SROIAAA to add an API connector. Covers
accounts, environment, the git workflow, and how two people add sources to
the same broker without stepping on each other.

The technical contract for a connector lives in
[adding-a-connector.md](adding-a-connector.md). This document is about
everything around it.

## Use your own accounts

Work under your own Unix account on the runtime host and your own GitHub
identity. Do not share a login, even between people who trust each other.

Trust is not the reason to separate accounts. Attribution is. When a
credential leaks, a query behaves unexpectedly, or something needs to be
revoked, the question is always *which person did this*, and a shared
account cannot answer it. The project has already recorded this failure
mode in two places: the broker's `caller_id` identifies a credential
rather than a person, and the gateway risk register carries the same
finding for shared API keys. Adding a third instance would be a choice, not
an accident.

Practically this means:

- your own shell account on the runtime host
- your own MindRouter API key, named for its purpose, so it can be revoked
  without affecting anyone else
- your own `~/.config/sroiaaa/env`, mode `0600`
- your own GitHub account with collaborator access on the repository

Shared *service* credentials such as a read-only monitoring account are a
different case and may reasonably be shared, since they identify a role
rather than a person. Personal credentials are not.

## Setup

### 1. Repository access

You need collaborator access on the repository, or a fork. For two
partners working closely, collaborator access and shared branches is
simpler than forks and avoids a round trip on every change.

```bash
git clone https://github.com/bindatype/SROIAAA.git
cd SROIAAA
go test ./...
```

If the tests pass you have a working toolchain. They need no credentials
and no network: every connector is tested against an in-process HTTP
server.

### 2. Credentials

Runtime configuration lives in a file you source explicitly. Never in
`~/.bashrc`, never in the repository.

```bash
mkdir -p ~/.config/sroiaaa && chmod 700 ~/.config/sroiaaa
umask 077
cat > ~/.config/sroiaaa/env <<'ENVEOF'
export MINDROUTER_API_KEY=...
export SROIAAA_MINDROUTER_ENDPOINT=http://localhost:8000
export SROIAAA_ZABBIX_ENDPOINT=https://zabbix.example.edu/api_jsonrpc.php
export ZABBIX_RO_TOKEN=...
export SROIAAA_WAZUH_ENDPOINT=https://wazuh.example.edu:55000
export WAZUH_API_USERNAME=...
export WAZUH_API_PASSWORD=...
ENVEOF
chmod 600 ~/.config/sroiaaa/env
```

Every line needs `export`. A variable that is only *set* is visible to your
interactive shell but is not inherited by the programs you run. This has
cost time on three separate occasions in this project, including once
where the failure looked like a broken credential rather than a missing
one.

### 3. Verify end to end

```bash
source ~/.config/sroiaaa/env
make eval-zabbix
```

This runs real questions against live monitoring data and grades the
answers. If it passes, your environment is correct and you have a working
baseline to compare against after you change something.

## Adding an API

Read [adding-a-connector.md](adding-a-connector.md) first. It defines the
`Connector` interface, the five files a new source touches, and the
invariants each connector must uphold. Those invariants are not style
preferences; each one exists because something produced a wrong answer
during development.

Then:

```bash
git checkout -b feat/<source>-connector
```

Build in this order. Each step is independently reviewable and the early
ones surface disagreements before you have written much:

1. **Declare the source and intents** in `internal/broker/types.go`. Small
   and worth doing first, because it is also how you claim the name.
2. **Add planning** in `internal/broker/router.go`, with tests. At this
   point the intent can be authorized and denied but nothing executes.
3. **Implement the connector** in `internal/connector/<source>.go`, with
   tests against `httptest`. No network, no credentials.
4. **Wire configuration** into `cmd/sroiaaa-broker-exec` and
   `cmd/sroiaaa-chat`.
5. **Expose the intent** to the model in `internal/orchestrator/session.go`
   — the tool schema enum and the system prompt, including what the intent
   does *not* cover.
6. **Add evaluation cases** to `scripts/`.

Then open a pull request. Keep `main` reviewable: it is currently pinned to
the commit under independent review, and merges should be deliberate.

## Working in parallel

Two people can add sources at the same time. Connector implementations are
independent files and will never conflict. Four files are shared, and all
four are registration points:

| File | What you add | Conflict risk |
|---|---|---|
| `internal/broker/types.go` | a `Source` and `Intent` constant | low, adjacent lines |
| `internal/broker/router.go` | a `case` in `Plan()` | low, adjacent cases |
| `cmd/sroiaaa-broker-exec/main.go` | a block in `buildConnectors` | low |
| `internal/orchestrator/session.go` | an enum entry and prompt text | **moderate**, the prompt is prose |

The conflicts are mechanical rather than semantic — both sides are adding
to a list — so they resolve easily. Two habits keep it painless:

- **Claim the name first.** Land a small pull request adding just the
  `Source` and `Intent` constants before building the rest. It reserves the
  name, makes the intent visible early, and gives the other person
  something to rebase onto instead of discovering a collision at merge.
- **Rebase before opening a pull request**, so conflicts surface on your
  branch rather than in review.

The system prompt is the one place where two additions can genuinely
disagree rather than merely collide, because it is prose describing what
the model may and may not do. Treat prompt changes as requiring the same
review attention as code: a careless edit there can undo a safety property
without failing a test.

### The refactor that would remove this friction

Dispatch is currently a `switch` in `router.Plan()` and a chain of `if`
blocks in `buildConnectors`. Moving to an explicit registry, where a source
registers itself and the shared files carry only a loop, would reduce the
shared surface to almost nothing.

This is already recorded as a planned step in the project notes for the
endpoint operation catalog, for the same reason: the centralized `switch`
is fine while the surface is small and becomes a bottleneck as it grows. A
second contributor is exactly the pressure that makes it worth doing. It is
not a prerequisite for the first new connector, but if a third source is
coming, do it before rather than after.

## Worked example: Request Tracker

What has to be settled before writing code.

**Which REST API.** RT 5.x has REST2 at `/REST/2.0/`, JSON, with
`Authorization: token <token>`. RT 4.x has REST1 at `/REST/1.0/`, a bespoke
line-oriented format that needs its own parser. Confirm the version first;
it changes the amount of work substantially.

**A read-only token on a dedicated account.** Not a personal login. RT can
modify tickets, so the credential should not be able to.

**Which queues are in scope.** An allowlist in configuration, not a
parameter a plan can set.

**Whether ticket bodies are in scope.** This is the decision that most
needs making before rather than after. Zabbix and Wazuh return operational
telemetry. RT returns human correspondence, which routinely contains user
details and credentials pasted into logs by people asking for help. The
safe default is metadata only — subject, queue, status, owner, dates — with
body text excluded unless there is a specific decision to include it. Once
evidence flows to a model it has left the building; decide first.

**Which operations are reachable.** RT is write-capable. The connector's
action table is the control: if `ticket.comment` and `ticket.resolve` are
not compiled in, they cannot be reached regardless of what a plan or a
model asks for. Do not rely on the credential being read-only as the only
safeguard.

### Why it is worth adding

The loop can already report that a host has had a filesystem panic since a
given date. The obvious next question is whether anyone is already working
on it, and a ticketing system is the only thing that can answer it.

A `tickets.for_host` intent would also be the first to combine two sources
in a single plan: monitoring state and human response side by side. That is
a genuinely different capability from either system alone, and it is the
point at which the broker's multi-step route plan earns the shape it
already has.
