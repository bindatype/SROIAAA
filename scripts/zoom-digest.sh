#!/bin/sh
# Post a morning digest into a Zoom Team Chat channel.
#
#   . ~/.config/sroiaaa/env
#   sh scripts/zoom-digest.sh            # ask, and post to Zoom
#   sh scripts/zoom-digest.sh -n         # ask, print here, post nothing
#   sh scripts/zoom-digest.sh -n Wazuh   # just that one section
#
# From cron, source the environment first; cron gets almost none of it:
#   0 7 * * 1-5 . $HOME/.config/sroiaaa/env && sh $HOME/sroiaaa-src/scripts/zoom-digest.sh
#
# The signature construction Zoom accepts was confirmed on 2026-08-30 and is
# the built-in default, so SROIAAA_ZOOM_SIGNATURE_VARIANT need not be set. If
# posting starts returning 401, run  sroiaaa-notify -probe  before assuming
# the secret is wrong.
#
# Read-only throughout. Nothing here modifies any system.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

DRY=0
case ${1:-} in
-n | --dry-run)
	DRY=1
	shift
	;;
-h | --help)
	sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
	exit 0
	;;
esac
# An optional substring selects one section, so testing a single question does
# not mean running all three.
ONLY=${1:-}

# Fail before asking anything. Without this the first missing variable surfaces
# from sroiaaa-notify at the end of a pipeline, after a question has already
# been answered, and reads as a Zoom problem rather than a missing source.
#
# ~/.config/sroiaaa/env is sourced explicitly and not from ~/.bashrc, so a
# fresh shell has none of these. That is the usual cause.
required="SROIAAA_MINDROUTER_ENDPOINT MINDROUTER_API_KEY SROIAAA_WAZUH_CRITICAL_GROUPS"
[ "$DRY" -eq 1 ] || required="$required SROIAAA_ZOOM_WEBHOOK_URL"
missing=
for var in $required; do
	eval "value=\${$var:-}"
	[ -n "$value" ] || missing="$missing $var"
done
if [ "$DRY" -eq 0 ] && [ -z "${SROIAAA_ZOOM_WEBHOOK_SECRET:-}${SROIAAA_ZOOM_WEBHOOK_TOKEN:-}" ]; then
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
[ "$DRY" -eq 1 ] || go build -o "$BIN/sroiaaa-notify" "$ROOT/cmd/sroiaaa-notify"

# A failed question must not post a cheerful empty message, and must not stop
# the questions after it. Each one stands or falls alone.
digest() {
	title=$1
	question=$2
	case $title in
	*"$ONLY"*) ;;
	*) return 0 ;;
	esac

	if answer=$("$BIN/sroiaaa-chat" -policy "$POLICY" -wazuh-insecure "$question" 2>&1); then
		body=$answer
	else
		title="$title (failed)"
		body=$(printf 'Could not answer "%s":\n%s' "$question" "$answer")
	fi

	if [ "$DRY" -eq 1 ]; then
		# Same text the channel would receive, marked so a dry run is never
		# mistaken for a real one in a scrollback.
		printf '\n--- %s --- (dry run, not posted)\n%s\n' "$title" "$body"
	else
		printf '%s\n' "$body" | "$BIN/sroiaaa-notify" -title "$title"
	fi
}

digest "Zabbix overnight" "what problems started since yesterday, and how many are there by severity?"
# Critical groups are set by SROIAAA_WAZUH_CRITICAL_GROUPS and marked in the
# evidence before the model sees it, so this asks for a report rather than a
# calculation.
digest "Wazuh agents" "how many agents are disconnected right now, and are any of them in a critical group? Name the critical ones."
# Not "the last 24 hours": runTBL2 lags ingestion by about a day, so that
# window holds only the leading edge and reads as an idle cluster every
# morning. A complete past day is the honest question.
digest "Scheduler" "for the most recent complete day in runTBL2: how many jobs completed and how many failed, and what was the median wait time for the cpu partition and for the gpu partition? Say which day, and give wait times in seconds and minutes."
