#!/bin/sh
# Ask SROIAAA a set of Zabbix questions chosen so that a wrong answer is
# reassuring rather than obviously broken.
#
# The useful ones are not the questions SROIAAA answers well. They are the ones
# where the plausible failure reads as good news: an empty window mistaken for a
# healthy fleet, a page mistaken for a population, a row count mistaken for a
# machine count. Each case below prints what to look for, so the answer can be
# judged rather than admired.
#
# Usage:
#   sh scripts/zabbix-probe.sh              # every case
#   sh scripts/zabbix-probe.sh trap         # only cases whose id contains "trap"
#   sh scripts/zabbix-probe.sh -l           # list the cases without asking
#
# Requires the same environment as the digest:
#   . $HOME/.config/sroiaaa/env
set -eu

POLICY="${SROIAAA_POLICY:-configs/broker-policy.example.json}"
CHAT="go run ./cmd/sroiaaa-chat -policy $POLICY -wazuh-insecure"

# id | question | what a good answer does | what a wrong answer looks like
cases='
narrow|Which hosts have lost their Zabbix agent?|Uses match rather than reading a general page. Reports triggers AND distinct hosts as separate numbers.|A list scraped from the first 25 rows of everything, or one number where two are needed.
trap-empty-window|Did any host lose its Zabbix agent since 5am today?|Says nothing OPENED or CLOSED in that window, then checks current problems and reports the agents that are down right now.|"No hosts lost their Zabbix agent" - the event log is empty because an ongoing outage writes nothing inside its own window.
trap-population|How many problems are active right now?|The full total from the census, explicitly distinguished from how many rows it was shown.|Any number equal to 25, 200, or a suspiciously round 20000. Those are limits, not counts.
breakdown|Which systems are in the worst shape right now?|Reads breakdown.events_by_host, names the top hosts with counts, and states that the breakdown is capped if it is.|A list of whichever hosts happened to be in the returned page, implying the rest are fine.
trap-rows-vs-hosts|How many machines currently have a Zabbix agent problem?|Answers with hosts_affected, and says how many triggers that is across.|The trigger count reported as a machine count. Several triggers fire on one host.
trap-double-count|How many problems started since yesterday?|Filters state to problem, so an incident that opened and closed is counted once.|Roughly double the true figure, from counting both the opening and the closing event.
severity|Are there any disaster-level problems right now?|A definite yes with the host, or a definite no backed by the severity census over ALL matching rows.|A no derived from not seeing one in the returned page.
trap-unknown-host|What is wrong with prattlebox42?|Says Zabbix has never heard of that host. It does not exist.|"No problems found" - which reads as an assurance about a machine nothing was ever checked on.
tense|What broke overnight, and what is still broken now?|Two different questions from two different intents: history for what changed, problems for what stands.|One intent answering both, which gets one of them wrong.
'

if [ "${1:-}" = "-l" ]; then
	echo "$cases" | while IFS='|' read -r id question _ _; do
		[ -n "$id" ] || continue
		printf '  %-20s %s\n' "$id" "$question"
	done
	exit 0
fi

required="SROIAAA_MINDROUTER_ENDPOINT MINDROUTER_API_KEY ZABBIX_RO_TOKEN SROIAAA_ZABBIX_ENDPOINT"
missing=""
for name in $required; do
	eval "value=\${$name:-}"
	[ -n "$value" ] || missing="$missing $name"
done
if [ -n "$missing" ]; then
	echo "zabbix-probe: missing environment:$missing" >&2
	echo "zabbix-probe: run  . \$HOME/.config/sroiaaa/env  first" >&2
	exit 2
fi

filter="${1:-}"
echo "$cases" | while IFS='|' read -r id question good bad; do
	[ -n "$id" ] || continue
	case "$id" in
	*"$filter"*) ;;
	*) continue ;;
	esac

	echo "═══ $id ═══════════════════════════════════════════════"
	echo "Q: $question"
	echo
	printf '%s\n' "$question" | $CHAT 2>/dev/null || echo "(the ask failed)"
	echo
	echo "  LOOK FOR: $good"
	echo "  WRONG IF: $bad"
	echo
done
