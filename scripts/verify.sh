#!/bin/sh
# Everything that must pass before anything reaches main, and nothing that
# needs a credential or a network.
#
#   make verify
#
# There is no CI. No hook, no workflow, nothing on GitHub runs a test: a green
# pull request page means only that nobody has looked. This script is the gate,
# and it is only a gate if somebody runs it.
#
# Every check runs inside `if` so a failure is recorded rather than aborting the
# run. scripts/check_entrypoints.sh shipped with `set -e` and stopped at its
# first failure, reporting nothing about the checks after it -- found only by
# breaking something on purpose. A gate that hides most of its own output on
# the first problem makes the second problem invisible.
#
# What this deliberately does NOT cover: whether a model behaves, and whether a
# connector agrees with the service behind it. Those need credentials and live
# data, and they are `make test-rt-live` and `make eval-rt-shape`. A tree that
# passes everything here can still be wrong about RT.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

pass=0
fail=0

ok()   { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; [ -n "$2" ] && printf '      %s\n' "$2"; }

unformatted=$(gofmt -l ./cmd ./internal 2>/dev/null)
if [ -z "$unformatted" ]; then
	ok "gofmt: every file formatted"
else
	bad "gofmt: unformatted files" "$(echo "$unformatted" | tr '\n' ' ')"
fi

if go build ./... >/dev/null 2>&1; then
	ok "go build"
else
	bad "go build" "$(go build ./... 2>&1 | head -3)"
fi

if go vet ./... >/dev/null 2>&1; then
	ok "go vet"
else
	bad "go vet" "$(go vet ./... 2>&1 | head -3)"
fi

if go test -count=1 ./... >/dev/null 2>&1; then
	ok "go test (all packages, uncached)"
else
	bad "go test" "$(go test -count=1 ./... 2>&1 | grep -E '^(---|FAIL|ok.*FAIL)' | head -5)"
fi

# Build-tagged code is compiled by nothing in the default path, so it rots in
# silence: a rename three packages away leaves it uncompilable for weeks and
# the first person to need it discovers that instead of the answer they wanted.
if go vet -tags rtlive ./internal/connector/ >/dev/null 2>&1; then
	ok "go vet -tags rtlive (live tests still compile)"
else
	bad "go vet -tags rtlive" "$(go vet -tags rtlive ./internal/connector/ 2>&1 | head -3)"
fi

# The live tests reach the network with real credentials. They must never join
# the default run, on any machine, including one with an environment sourced.
leaked=$(go test ./internal/connector/ -list '.*' 2>/dev/null | grep -c RTLive)
if [ "$leaked" = "0" ]; then
	ok "live tests excluded from the default run"
else
	bad "live tests leak into the default run" "$leaked RTLive test(s) would run without being asked for"
fi

if sh ./scripts/check_entrypoints.sh >/dev/null 2>&1; then
	ok "entry points (install, uninstall, ask startup)"
else
	bad "entry points" "$(sh ./scripts/check_entrypoints.sh 2>&1 | grep -i fail | head -3)"
fi

# Import rather than parse. Parsing catches a syntax error and nothing else:
# six of these scripts once referred to an undefined name at module level --
# every one of them died on its first line -- and this check reported them all
# green, because the file parsed. Importing runs the module top level, which is
# where a harness keeps the names it resolves before it does any work. Nothing
# here touches the network: every script defers that to main().
badpy=""
for script in scripts/*.py; do
	name=$(basename "$script" .py)
	err=$(cd scripts && python3 -c "import $name" 2>&1) || badpy="$badpy
  $script: $(printf '%s' "$err" | tail -1)"
done
if [ -z "$badpy" ]; then
	ok "evaluation harnesses import"
else
	bad "evaluation harnesses do not import" "$badpy"
fi

# Shell scripts are checked for syntax the way the Python ones are checked for
# import. Nothing else runs them: bin/zoom-digest.sh fires from cron at 04:45,
# and a typo in it surfaces as a line in a log nobody reads -- which is exactly
# how it went six days without posting.
badsh=""
for script in bin/*.sh scripts/*.sh; do
	[ -e "$script" ] || continue
	err=$(sh -n "$script" 2>&1) || badsh="$badsh
  $script: $(printf '%s' "$err" | head -1)"
done
if [ -z "$badsh" ]; then
	ok "shell scripts parse"
else
	bad "shell scripts do not parse" "$badsh"
fi

# The grader decides what every RT shape result means, and nothing in a run
# notices when a grader is wrong: the numbers come out and look like results.
if python3 ./scripts/eval_rt_shape.py --self-test >/dev/null 2>&1; then
	ok "RT shape grader self-test"
else
	bad "RT shape grader self-test" "$(python3 ./scripts/eval_rt_shape.py --self-test 2>&1 | head -3)"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -gt 0 ]; then
	printf 'verify: NOT ready for main\n'
	exit 1
fi
printf 'verify: credential-free checks pass. Live behaviour is not covered:\n'
printf '        make test-rt-live   RT invariants against the live instance\n'
printf '        make eval-rt-shape  whether the model bounds a ticket-age question\n'
