#!/usr/bin/env python3
"""A/B the pre-Zabbix prompt against the current one, on the same code.

Usage:
    source ~/.config/sroiaaa/env
    python3 scripts/eval_prompt_ab.py [model]
    RUNS=5 python3 scripts/eval_prompt_ab.py gemma4:31b

What this does and does not measure
-----------------------------------
Both arms run the CURRENT binary. Only the prompt differs. That is deliberate
and it is also the only honest option: the new prompt names evidence fields
(`total_ignoring_time_bound`, `breakdown.events_by_host`, `hosts_affected`)
that the old code never emitted, so running the old prompt on the old code
would compare two changes at once and tell you nothing about either.

So the question here is narrow and worth asking: given that the connector now
computes the aggregates and warnings, does the prompt still earn its added
length, or does the richer evidence carry the model on its own?

The cases are the reassuring failures -- the ones where a wrong answer reads as
good news. A prompt rule that only helps on questions SROIAAA already answered
well is not worth 24 lines of a budget with 9.7 KB of headroom.

Ground truth is computed live, immediately before each run, because these
counts move: the active problem total was observed at 1841, 1458, 1846, 1844
and 1850 across a single afternoon.
"""
import datetime, json, os, ssl, subprocess, sys, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_common import build_chat, normalize, require_env, write_report

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPT = os.path.join(ROOT, "internal", "orchestrator", "prompt.md")
# The commit before the Zabbix query-control work began.
BASELINE_REV = os.environ.get("BASELINE_REV", "e94a4dd")
RUNS = int(os.environ.get("RUNS", "3"))
DEFAULT_MODEL = os.environ.get("EVAL_MODEL", "gemma4:31b")

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

AGENT_MATCH = "Zabbix agent is not available"


def zabbix(method, params):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "id": 1,
                       "params": params}).encode()
    req = urllib.request.Request(
        os.environ["SROIAAA_ZABBIX_ENDPOINT"], data=body, method="POST",
        headers={"Content-Type": "application/json-rpc",
                 "Authorization": "Bearer " + os.environ["ZABBIX_RO_TOKEN"]})
    return json.load(urllib.request.urlopen(req, context=_CTX, timeout=60))["result"]


FIRING = {"only_true": True, "monitored": True, "skipDependent": True}


def agents_down():
    """Triggers firing now for an unavailable agent, and the hosts under them."""
    rows = zabbix("trigger.get", dict(FIRING, search={"description": AGENT_MATCH},
                                      output=["triggerid"], selectHosts=["host"],
                                      limit=5000))
    hosts = {r["hosts"][0]["host"] for r in rows if r.get("hosts")}
    return len(rows), len(hosts)


def problems_now():
    return int(zabbix("trigger.get", dict(FIRING, countOutput=True)))


def worst_host():
    rows = zabbix("trigger.get", dict(FIRING, min_severity=4, output=["triggerid"],
                                      selectHosts=["host"], limit=5000))
    counts = {}
    for row in rows:
        if row.get("hosts"):
            counts[row["hosts"][0]["host"]] = counts.get(row["hosts"][0]["host"], 0) + 1
    return max(counts, key=counts.get) if counts else None


def opened_since_yesterday():
    midnight = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    since = int((midnight - datetime.timedelta(days=1)).timestamp())
    return int(zabbix("event.get", {"source": 0, "object": 0, "time_from": since,
                                    "value": [1], "countOutput": True}))


def says(answer, number):
    """Whether the answer states this integer, tolerating 1,234 and 1234."""
    text = normalize(answer)
    return str(number) in text.replace(",", "") or "{:,}".format(number) in text


def policy_path():
    """The deployed policy where there is one, the example otherwise.

    The other eval scripts assume ~/.config/sroiaaa/policy.json exists. It does
    on sgtstubby and does not on a fresh clone, and failing over to the example
    keeps the suite runnable in both places rather than only where it was
    written.
    """
    deployed = os.path.expanduser("~/.config/sroiaaa/policy.json")
    if os.path.exists(deployed):
        return deployed
    return os.path.join(ROOT, "configs", "broker-policy.example.json")


def ask(binary, model, prompt_path, question):
    env = dict(os.environ, SROIAAA_PROMPT=prompt_path)
    started = time.time()
    try:
        proc = subprocess.run(
            [binary, "-policy", policy_path(), "-wazuh-insecure", "-model", model, question],
            capture_output=True, text=True, timeout=420, env=env, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return "", round(time.time() - started, 1)
    return proc.stdout.strip(), round(time.time() - started, 1)


# Each case grades against a number computed seconds earlier, not against a
# fixed string. `lead` marks the cases where being right in the body but
# reassuring in the first sentence is itself the failure.
def build_cases():
    down_triggers, down_hosts = agents_down()
    return [
        {"id": "false_allclear", "lead": True,
         "q": "Did any host lose its Zabbix agent since 5am today?",
         "why": "The event log is empty because an ongoing outage writes nothing inside its own window.",
         "must_number": down_hosts,
         "forbid_lead": ["no host", "none", "no hosts"]},
        {"id": "narrow",
         "q": "Which hosts have lost their Zabbix agent?",
         "why": "Needs match rather than reading down a general page.",
         "must_number": down_triggers},
        {"id": "rows_vs_hosts",
         "q": "How many machines currently have a Zabbix agent problem?",
         "why": "Several triggers fire on one host; the trigger count is not the machine count.",
         "must_number": down_hosts},
        {"id": "population",
         "q": "How many problems are active right now?",
         "why": "A page size reported as a population.",
         "must_number": problems_now(), "tolerance": 0.03,
         "forbid": ["25 problems", "200 problems"]},
        {"id": "worst_hosts",
         "q": "Which systems are in the worst shape right now?",
         "why": "Needs the per-host breakdown, not whichever hosts landed in the page.",
         "must_text": [worst_host()]},
        {"id": "double_count",
         "q": "How many problems started since yesterday?",
         "why": "Counting both the opening and closing event doubles the figure.",
         "must_number": opened_since_yesterday(), "tolerance": 0.10},
    ]


def grade(case, answer):
    faults = []
    if not answer:
        return ["empty"]
    text = normalize(answer)

    if "must_number" in case and case["must_number"] is not None:
        want = case["must_number"]
        tolerance = case.get("tolerance", 0)
        ok = says(answer, want)
        if not ok and tolerance:
            # A volatile count only has to land close, but the answer must
            # still contain some number: "several" is not a measurement.
            digits = [int(t) for t in normalize(answer).replace(",", "").split()
                      if t.isdigit()]
            ok = any(abs(d - want) <= max(1, want * tolerance) for d in digits)
        if not ok:
            faults.append("missing:%s" % want)

    for token in case.get("must_text", []):
        if token and token.lower() not in text:
            faults.append("missing:%s" % token)
    for token in case.get("forbid", []):
        if token.lower() in text:
            faults.append("said:%s" % token)

    # The lead check: an answer that is right in the body and reassuring in its
    # first sentence still misleads a reader who stops there, and these go to a
    # chat channel where people skim.
    if case.get("lead"):
        first = text.split(".")[0]
        if any(p in first for p in case.get("forbid_lead", [])):
            faults.append("lead-is-reassuring")
    return faults


def main():
    require_env()
    model = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODEL
    binary = build_chat()

    baseline = subprocess.run(["git", "show", "%s:internal/orchestrator/prompt.md" % BASELINE_REV],
                              cwd=ROOT, capture_output=True, text=True)
    if baseline.returncode != 0:
        sys.exit("cannot read the baseline prompt at %s: %s" % (BASELINE_REV, baseline.stderr.strip()))
    old_path = os.path.join(ROOT, "runtime", "prompt-baseline.md")
    os.makedirs(os.path.dirname(old_path), exist_ok=True)
    with open(old_path, "w") as fh:
        fh.write(baseline.stdout)
    current = open(PROMPT).read()

    arms = [("old", old_path, len(baseline.stdout)), ("new", PROMPT, len(current))]
    print("model: %s   %d runs per case   same binary, prompt is the only variable" % (model, RUNS))
    print("  old prompt  %s  %d chars" % (BASELINE_REV, len(baseline.stdout)))
    print("  new prompt  working tree  %d chars  (+%d)\n"
          % (len(current), len(current) - len(baseline.stdout)), flush=True)

    cases = build_cases()
    tally = {name: {} for name, _, _ in arms}
    for case in cases:
        print("── %s ─ %s" % (case["id"], case["why"]), flush=True)
        for name, path, _ in arms:
            passes, seconds = 0, []
            for _ in range(RUNS):
                answer, took = ask(binary, model, path, case["q"])
                seconds.append(took)
                faults = grade(case, answer)
                if not faults:
                    passes += 1
                else:
                    print("     %-3s FAIL %-28s %s" % (name, ";".join(faults),
                                                       answer[:90].replace("\n", " ")), flush=True)
            tally[name][case["id"]] = passes
            print("     %-3s %d/%d  avg %.1fs" % (name, passes, RUNS,
                                                  sum(seconds) / len(seconds)), flush=True)
        print(flush=True)

    lines = ["Generated %s" % datetime.datetime.now().isoformat(timespec="seconds"), "",
             "Model `%s`, %d runs per case. **Both arms run the same binary**; the prompt"
             " is the only variable, because the new prompt names evidence fields the old"
             " code never emitted." % (model, RUNS), "",
             "Old prompt `%s`, %d chars. New prompt, %d chars (+%d)."
             % (BASELINE_REV, len(baseline.stdout), len(current), len(current) - len(baseline.stdout)), "",
             "| case | old | new | what it catches |", "|---|---|---|---|"]
    for case in cases:
        lines.append("| `%s` | %d/%d | %d/%d | %s |" % (
            case["id"], tally["old"][case["id"]], RUNS,
            tally["new"][case["id"]], RUNS, case["why"]))
    old_total = sum(tally["old"].values())
    new_total = sum(tally["new"].values())
    lines += ["", "**Total: old %d/%d, new %d/%d.**"
              % (old_total, len(cases) * RUNS, new_total, len(cases) * RUNS)]

    print("===== old %d/%d   new %d/%d =====" % (old_total, len(cases) * RUNS,
                                                 new_total, len(cases) * RUNS))
    write_report("eval-prompt-ab.md", "Prompt A/B: pre-Zabbix baseline vs current", lines)


if __name__ == "__main__":
    main()
