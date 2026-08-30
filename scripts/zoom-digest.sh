#!/bin/sh
# Post a morning digest into a Zoom Team Chat channel.
#
#   source ~/.config/sroiaaa/env
#   sh scripts/zoom-digest.sh
#
# From cron, source the environment first; cron gets almost none of it:
#   0 7 * * 1-5 . $HOME/.config/sroiaaa/env && sh $HOME/sroiaaa/scripts/zoom-digest.sh
#
# The signature construction Zoom accepts was confirmed on 2026-08-30 and is
# the built-in default, so SROIAAA_ZOOM_SIGNATURE_VARIANT need not be set. If
# posting starts returning 401, run  sroiaaa-notify -probe  before assuming
# the secret is wrong.
#
# Read-only throughout. Nothing here modifies any system.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# Fail before asking anything. Without this the first missing variable surfaces
# from sroiaaa-notify at the end of a pipeline, after a question has already
# been answered, and reads as a Zoom problem rather than a missing source.
#
# ~/.config/sroiaaa/env is sourced explicitly and not from ~/.bashrc, so a
# fresh shell has none of these. That is the usual cause.
missing=
for var in SROIAAA_MINDROUTER_ENDPOINT MINDROUTER_API_KEY SROIAAA_ZOOM_WEBHOOK_URL; do
	eval "value=\${$var:-}"
	[ -n "$value" ] || missing="$missing $var"
done
if [ -z "${SROIAAA_ZOOM_WEBHOOK_SECRET:-}${SROIAAA_ZOOM_WEBHOOK_TOKEN:-}" ]; then
	missing="$missing SROIAAA_ZOOM_WEBHOOK_SECRET"
fi
if [ -n "$missing" ]; then
	echo "zoom-digest: not set in this environment:$missing" >&2
	echo "zoom-digest: run  . ~/.config/sroiaaa/env  first" >&2
	echo "zoom-digest: (a variable set in ~/.bashrc without export is invisible here)" >&2
	exit 2
fi
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
# Not "the last 24 hours": runTBL2 lags ingestion by about a day, so that
# window holds only the leading edge and reads as an idle cluster every
# morning. A complete past day is the honest question.
digest "Scheduler" "how many jobs failed and how many completed on the most recent complete day in runTBL2? Say which day."
