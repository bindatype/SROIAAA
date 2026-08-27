#!/usr/bin/env python3
"""Grade tool-capable models on the SROIAAA evidence loop.

Usage:
    source ~/.config/sroiaaa/env
    python3 scripts/eval_models.py [model ...]

Each model is scored on whether it routed to the correct intent, extracted a
host where one was needed, and reported figures matching the authoritative
sources. Latency is reported because intent routing turns out not to
discriminate much between model sizes, which makes speed the deciding factor.
"""
import datetime, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_common import (ask, build_chat, normalize, numbers_in, require_env,
                         wazuh_agent_counts, write_report, zabbix_count)

DEFAULT_MODELS = [
    "qwen3.6:35b",
    "mistral-small3.2:latest",
    "qwen2.5:72b",
    "llama3.3:latest",
    "llama3.1:405b",
]


def main():
    require_env()
    models = sys.argv[1:] or DEFAULT_MODELS
    binary = build_chat()

    active, disconnected = wazuh_agent_counts()
    print("ground truth: active=%d disconnected=%d" % (active, disconnected), flush=True)

    cases = [
        {"id": "fleet_counts", "intent": "fleet.inventory",
         "q": "how many wazuh agents are disconnected, and how many are active?",
         "must": [str(disconnected), str(active)]},
        {"id": "single_host", "intent": "agent.status",
         "q": "is zabbixproxy01.arc.gwu.edu healthy?",
         "host": "zabbixproxy01.arc.gwu.edu", "must": ["disconnected"]},
        {"id": "problem_total", "intent": "monitoring.problems",
         "q": "how many active problems are there in total?", "volatile": True},
        {"id": "whats_broken", "intent": "monitoring.problems",
         "q": "what is broken right now? mention the most severe issue."},
    ]

    rows = []
    for model in models:
        for case in cases:
            before = zabbix_count() if case.get("volatile") else None
            answer, intent, host, seconds = ask(binary, model, case["q"])
            after = zabbix_count() if case.get("volatile") else None

            faults = []
            if intent != case["intent"]:
                faults.append("intent=%s" % (intent or "none"))
            if case.get("host") and host != case["host"]:
                faults.append("host=%s" % (host or "none"))
            text = normalize(answer)
            for token in case.get("must", []):
                if token.lower() not in text:
                    faults.append("missing:%s" % token)
            if before is not None:
                low, high = min(before, after), max(before, after)
                if not any(low <= n <= high for n in numbers_in(text)):
                    faults.append("count outside [%d,%d]" % (low, high))

            rows.append({"model": model, "case": case["id"], "seconds": seconds,
                         "faults": faults, "answer": answer})
            print("  %-28s %-14s %6.1fs  %s" % (
                model, case["id"], seconds,
                "PASS" if not faults else "FAIL " + "; ".join(faults)), flush=True)

    lines = ["Generated %s" % datetime.datetime.now().isoformat(timespec="seconds"),
             "", "| model | passed | avg seconds |", "|---|---|---|"]
    print("\n%-28s %8s %8s" % ("model", "passed", "avg s"))
    for model in models:
        mine = [r for r in rows if r["model"] == model]
        passed = sum(1 for r in mine if not r["faults"])
        avg = sum(r["seconds"] for r in mine) / max(len(mine), 1)
        print("%-28s %6d/%d %7.1f" % (model, passed, len(mine), avg))
        lines.append("| `%s` | %d/%d | %.1f |" % (model, passed, len(mine), avg))

    lines += ["", "## Failures", ""]
    for row in rows:
        if row["faults"]:
            lines.append("- `%s` / `%s`: %s" % (row["model"], row["case"],
                                                "; ".join(row["faults"])))
    write_report("eval-models.md", "SROIAAA model survey", lines)


if __name__ == "__main__":
    main()
