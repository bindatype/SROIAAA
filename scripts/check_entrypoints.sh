#!/bin/sh
# The contributor-facing path, checked the way the Go code is checked.
#
# `go test ./...` covers the packages and now the commands, but the first thing
# a new contributor touches is none of those: it is `make install` and then
# typing `ask`. That path has broken twice -- a dangling symlink after bin/ask
# moved, and a `make uninstall` recipe with an unterminated quote that removed
# the file and then failed -- and neither showed up in any test.
#
# Needs no credentials and no network.
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PREFIX=$(mktemp -d "${TMPDIR:-/tmp}/sroiaaa-entrypoints.XXXXXX")
ENVDIR=$(mktemp -d "${TMPDIR:-/tmp}/sroiaaa-env.XXXXXX")
trap 'rm -rf "$PREFIX" "$ENVDIR"' EXIT INT TERM

failures=0

# Every check runs inside `if`, so a failing one is recorded rather than
# aborting the run. The first version of this script used `set -e` and stopped
# at the first failure, reporting nothing about it -- which is the same defect
# it exists to catch, in the checker itself.
check() {
	description=$1
	shift
	if "$@" >/dev/null 2>&1; then
		printf 'ok    %s\n' "$description"
	else
		printf 'FAIL  %s\n' "$description"
		failures=$((failures + 1))
	fi
}

# A shell entry point with a syntax error is discovered by whoever runs it
# next, which for one of these is cron at 04:45.
parses() {
	if head -n 1 "$1" | grep -q bash; then
		bash -n "$1"
	else
		sh -n "$1"
	fi
}

says() {
	SROIAAA_ENV=$1 "$PREFIX/ask" test 2>&1 | grep -q -- "$2"
}

for script in "$ROOT"/bin/* "$ROOT"/scripts/*.sh; do
	[ -f "$script" ] || continue
	head -n 1 "$script" | grep -q '^#!' || continue
	name=${script#"$ROOT"/}
	check "parses: $name" parses "$script"
	check "executable: $name" test -x "$script"
done

check "make install succeeds" make -C "$ROOT" install PREFIX="$PREFIX"
check "install leaves a working symlink, not a dangling one" test -x "$PREFIX/ask"

# The operator-facing refusals must name what to fix, rather than failing
# somewhere inside Go's module resolution.
: > "$ENVDIR/empty"
check "missing env file is reported by name" says "$ENVDIR/absent" "no environment file"
check "an env file missing exports names the variables" says "$ENVDIR/empty" SROIAAA_MINDROUTER_ENDPOINT

check "make uninstall succeeds" make -C "$ROOT" uninstall PREFIX="$PREFIX"
check "uninstall removes the symlink" test ! -e "$PREFIX/ask"

printf '\n'
if [ "$failures" -eq 0 ]; then
	printf 'entry points: all checks passed\n'
else
	printf 'entry points: %d check(s) failed\n' "$failures"
	exit 1
fi
