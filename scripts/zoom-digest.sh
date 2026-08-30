#!/bin/sh
# Post a morning digest into a Zoom Team Chat channel.
#
#   source ~/.config/sroiaaa/env
#   sh scripts/zoom-digest.sh
#
# From cron, source the environment first; cron gets almost none of it:
#   0 7 * * 1-5 . $HOME/.config/sroiaaa/env && sh $HOME/sroiaaa/scripts/zoom-digest.sh
#
# Read-only throughout. Nothing here modifies any system.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
POLICY=${SROIAAA_POLICY:-"$ROOT/configs/broker-policy.example.json"}
BIN=${SROIAAA_BIN:-"$ROOT/runtime"}

mkdir -p "$BIN"
go build -o "$BIN/sroiaaa-chat" "$ROOT/cmd/sroiaaa-chat"
go build -o "$BIN/sroiaaa-notify" "$ROOT/cmd/sroiaaa-notify"

# A failed question must not post a cheerful empty message, and must not stop
# the questions after it. Each one stands or falls alone.
digest() {
	title=$1
	question=$2
	if answer=$("$BIN/sroiaaa-chat" -policy "$POLICY" -wazuh-insecure "$question" 2>&1); then
		printf '%s\n' "$answer" | "$BIN/sroiaaa-notify" -title "$title"
	else
		printf 'Could not answer "%s":\n%s\n' "$question" "$answer" |
			"$BIN/sroiaaa-notify" -title "$title (failed)"
	fi
}

digest "Zabbix overnight" "what problems started since yesterday, and how many are there by severity?"
digest "Wazuh agents" "how many agents are disconnected right now?"
digest "Scheduler" "how many jobs failed in the last 24 hours, and how many completed?"
