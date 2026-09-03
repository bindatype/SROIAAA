#!/usr/bin/env python3
"""Does the model bound a question about ticket age, and leave others alone?

The RT answer that prompted this was not a counting error. Asked how many
tickets are older than 60 days grouped by owner, the model proposed an
unbounded `tickets.open`, received 100 of 428 matching tickets, and tallied
dates and owners off that page. Every deterministic layer was correct. The
defect was in the shape of the request.

So this grades the request, not the answer. The shape is read from the trace
the model actually produced, which makes the primary metric exact: there is no
prose to interpret and no grader to be wrong about it.

Three outcomes, not two. `since` where `until` belongs answers the opposite
question -- tickets NEWER than the bound -- and reads perfectly plausible
either way. Folding that into "did not pass" would hide the one result that
should change what happens next.

Controls matter as much as targets. A prompt that teaches "reach for until"
can overshoot into bounding questions that must not be bounded, which is the
trap `fleet.inventory` already has. Without questions that must come back
UNBOUNDED, this harness could only ever report success.

    make eval-rt-shape                 # needs RT and MindRouter configured
    python3 scripts/eval_rt_shape.py --self-test   # grader only, no credentials
"""
import argparse, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_common as common

TICKET_INTENTS = ("tickets.open", "tickets.for_host")

# Five phrasings of the same question, because the failure may be specific to
# wording, and three controls that must not acquire a bound.
CASES = [
    ("age", "how many tickets in RT that are older than 60 days group them by owner"),
    ("age", "which open tickets have been open more than two months, by owner?"),
    ("age", "show me aging RT tickets grouped by who owns them"),
    ("age", "how many open tickets were created before July?"),
    ("age", "what is sitting in the RT queues the longest?"),
    ("now", "how many open tickets are there right now?"),
    ("now", "who owns the most open RT tickets?"),
    ("now", "are there any open tickets for dss01?"),
]

BOUNDED, UNBOUNDED, INVERTED, BOTH, NOT_RT = (
    "bounded", "unbounded", "inverted", "both", "not-rt")


def classify(args):
    """Classify one proposal. Pure, so the self-test can pin it."""
    intent = str(args.get("intent", "")).strip().lower()
    if intent not in TICKET_INTENTS:
        return NOT_RT
    since = str(args.get("since", "") or "").strip()
    until = str(args.get("until", "") or "").strip()
    if since and until:
        return BOTH
    if until:
        return BOUNDED
    if since:
        return INVERTED
    return UNBOUNDED


# Expected outcome per case kind. BOTH is not wrong for an age question -- a
# window is narrower than a ray and still answers it -- so it is scored as a
# pass and reported separately rather than silently merged.
PASSING = {"age": (BOUNDED, BOTH), "now": (UNBOUNDED,)}


SELF_TEST = [
    ({"intent": "tickets.open", "until": "60d"}, BOUNDED),
    ({"intent": "tickets.open", "until": "2026-07-04"}, BOUNDED),
    ({"intent": "tickets.for_host", "host": "dss01", "until": "60d"}, BOUNDED),
    ({"intent": "tickets.open", "since": "60d"}, INVERTED),
    ({"intent": "tickets.open"}, UNBOUNDED),
    ({"intent": "tickets.open", "since": "", "until": ""}, UNBOUNDED),
    ({"intent": "tickets.open", "since": "90d", "until": "60d"}, BOTH),
    ({"intent": "monitoring.problems", "until": "60d"}, NOT_RT),
    ({"intent": "TICKETS.OPEN", "until": "60d"}, BOUNDED),
    ({"intent": "tickets.open", "until": None}, UNBOUNDED),
    ({}, NOT_RT),
]


def self_test():
    """Check the grader before trusting it against a model.

    An evaluation in this project once failed correct answers over a thousands
    separator and a regex that could not match a single digit. A grader is
    code, it is written quickly, and nothing else in the run will notice when
    it is wrong -- the numbers simply come out and look like results.
    """
    failures = []
    for args, want in SELF_TEST:
        got = classify(args)
        if got != want:
            failures.append("classify(%r) = %s, want %s" % (args, got, want))

    # The parser is half the grader, and it reads real trace text.
    trace = 'x\nintent_proposed {"intent":"tickets.open","until":"60d"}\nmore\n'
    if common.proposed_args(trace) != {"intent": "tickets.open", "until": "60d"}:
        failures.append("proposed_args did not read a well-formed trace line")
    if common.proposed_args("no proposal here") != {}:
        failures.append("proposed_args invented arguments from a trace with none")

    for line in failures:
        print("SELF-TEST FAIL: " + line)
    print("grader self-test: %d checks, %d failed" % (len(SELF_TEST) + 2, len(failures)))
    return not failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true",
                        help="check the grader and exit; needs no credentials")
    parser.add_argument("--runs", type=int, default=5,
                        help="runs per case (default 5)")
    parser.add_argument("--model", default=os.environ.get("SROIAAA_EVAL_MODEL", "gemma4:31b"))
    options = parser.parse_args()

    if not self_test():
        sys.exit("grader is wrong; fix it before measuring a model with it")
    if options.self_test:
        return

    common.require_env()
    for name in ("SROIAAA_RT_ENDPOINT", "RT_API_TOKEN", "SROIAAA_RT_QUEUES"):
        if not os.environ.get(name):
            sys.exit("%s is not set (and must be exported); without RT configured the "
                     "intents are withheld from the model and every case would refuse "
                     "for a reason that has nothing to do with what is being measured" % name)

    binary = common.build_chat()
    rows, tally = [], {}
    for kind, question in CASES:
        outcomes = []
        for _ in range(options.runs):
            answer, args, elapsed = common.ask_args(binary, options.model, question)
            outcome = classify(args)
            outcomes.append(outcome)
            tally[outcome] = tally.get(outcome, 0) + 1
            print("  %-4s %-9s %5.1fs  %s" % (kind, outcome, elapsed, question[:52]),
                  file=sys.stderr)
            if outcome == INVERTED:
                # Worth surfacing immediately: it answers the opposite question
                # and the prose reads plausible either way.
                print("       INVERTED -> %s" % (answer[:100] or "(no answer)"), file=sys.stderr)
        rows.append((kind, question, outcomes))

    lines = ["Model: `%s`, %d runs per case." % (options.model, options.runs), ""]
    lines.append("`bounded` is an `until` with no `since`; `inverted` is a `since` where")
    lines.append("`until` belongs, which answers the opposite question; `both` is a window,")
    lines.append("narrower than needed but not wrong.")
    lines.append("")
    lines.append("| Kind | Question | Passed | Outcomes |")
    lines.append("|---|---|---|---|")

    failed_cases = 0
    for kind, question, outcomes in rows:
        passing = PASSING[kind]
        passed = sum(1 for o in outcomes if o in passing)
        if passed < len(outcomes):
            failed_cases += 1
        spread = ", ".join("%s x%d" % (o, outcomes.count(o)) for o in sorted(set(outcomes)))
        lines.append("| %s | %s | %d/%d | %s |" % (kind, question, passed, len(outcomes), spread))

    lines += ["", "Totals: " + ", ".join("%s %d" % (k, tally[k]) for k in sorted(tally)), ""]
    if failed_cases == 0:
        lines.append("Every case behaved as intended. Note what this does and does not show:")
        lines.append("the model proposed the right shape on this revision. It does not show")
        lines.append("the prompt change caused it -- that needs the same suite against")
        lines.append("`fbef98f`, which is Tier 3.")
    else:
        lines.append("%d of %d cases did not behave as intended. An `age` case coming back"
                     % (failed_cases, len(rows)))
        lines.append("`unbounded` is the original defect surviving. A `now` case coming back")
        lines.append("`bounded` is the overshoot the controls exist to catch, and is a")
        lines.append("regression introduced by the fix rather than a leftover.")

    path = common.write_report("rt-shape.md", "RT request shape", lines)
    print("\n".join(lines))
    print("\nreport: %s" % path, file=sys.stderr)
    sys.exit(1 if failed_cases else 0)


if __name__ == "__main__":
    main()
