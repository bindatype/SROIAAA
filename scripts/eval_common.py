"""Shared helpers for SROIAAA evidence-loop evaluations.

Ground truth is always fetched live rather than hard coded. Fleet counts are
stable enough to compare directly; problem counts move continuously, so they
are bounded by sampling before and after each call.
"""
import base64, json, os, re, ssl, subprocess, sys, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_POLICY = os.path.join(ROOT, "configs", "broker-policy.example.json")
RUNTIME = os.path.join(ROOT, "runtime")

# The Wazuh manager presents a self-signed certificate; see the Wazuh
# Interaction Guide. Verification is disabled only for these ground-truth
# probes, which is the same posture the connector requires an explicit flag for.
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

REQUIRED_ENV = ["SROIAAA_ZABBIX_ENDPOINT", "ZABBIX_RO_TOKEN",
                "SROIAAA_WAZUH_ENDPOINT", "WAZUH_API_USERNAME",
                "WAZUH_API_PASSWORD", "MINDROUTER_API_KEY",
                "SROIAAA_MINDROUTER_ENDPOINT"]


def require_env():
    missing = [v for v in REQUIRED_ENV if not os.environ.get(v)]
    if missing:
        sys.exit("missing environment: %s\n"
                 "these must be exported, not merely set; try "
                 "'source ~/.config/sroiaaa/env'" % ", ".join(missing))


def build_chat():
    """Build the chat binary into runtime/ so evaluations test current code."""
    os.makedirs(RUNTIME, exist_ok=True)
    binary = os.path.join(RUNTIME, "sroiaaa-chat")
    subprocess.run(["go", "build", "-o", binary, "./cmd/sroiaaa-chat"],
                   cwd=ROOT, check=True)
    return binary


def zabbix_count(host=None):
    params = {"countOutput": True, "only_true": True, "monitored": True,
              "skipDependent": True}
    if host:
        params["host"] = host
    body = json.dumps({"jsonrpc": "2.0", "method": "trigger.get", "id": 1,
                       "params": params}).encode()
    req = urllib.request.Request(
        os.environ["SROIAAA_ZABBIX_ENDPOINT"], data=body, method="POST",
        headers={"Content-Type": "application/json-rpc",
                 "Authorization": "Bearer " + os.environ["ZABBIX_RO_TOKEN"]})
    return int(json.load(urllib.request.urlopen(req, context=_CTX, timeout=30))["result"])


def wazuh_agent_counts():
    base = os.environ["SROIAAA_WAZUH_ENDPOINT"].rstrip("/")
    cred = base64.b64encode(("%s:%s" % (
        os.environ["WAZUH_API_USERNAME"], os.environ["WAZUH_API_PASSWORD"])).encode()).decode()
    req = urllib.request.Request(base + "/security/user/authenticate?raw=true",
                                 method="POST",
                                 headers={"Authorization": "Basic " + cred})
    token = urllib.request.urlopen(req, context=_CTX, timeout=30).read().decode().strip()
    req = urllib.request.Request(base + "/agents/summary/status",
                                 headers={"Authorization": "Bearer " + token})
    data = json.load(urllib.request.urlopen(req, context=_CTX, timeout=30))
    conn = data["data"]["connection"]
    return conn["active"], conn["disconnected"]


def normalize(text):
    """Strip thousands separators so 1,846 and 1846 compare equal."""
    return re.sub(r"(?<=\d),(?=\d)", "", text).lower()


def numbers_in(text):
    return [int(n) for n in re.findall(r"\b(\d{1,7})\b", text)]


def states_a_number(text, expected, tolerance=0.01):
    """Whether the answer states a value close to expected.

    Substring matching fails answers that are right: a model reporting 11.09
    against a ground truth rounded to 11.1 is not wrong, and neither is one
    writing 1,846 for 1846. Compare numerically, with a small tolerance for
    rounding.
    """
    try:
        want = float(str(expected).replace(",", ""))
    except ValueError:
        return str(expected).lower() in normalize(text)
    for found in re.findall(r"\d+(?:\.\d+)?", normalize(text)):
        value = float(found)
        if want == 0:
            if value == 0:
                return True
            continue
        if abs(value - want) / abs(want) <= tolerance:
            return True
    return False


def ask(binary, model, question, policy=DEFAULT_POLICY, timeout=420):
    """Run one question and return (answer, proposed_intent, host, seconds)."""
    import time
    started = time.time()
    try:
        proc = subprocess.run(
            [binary, "-policy", policy, "-model", model, "-trace",
             "-wazuh-insecure", question],
            capture_output=True, text=True, timeout=timeout)
        answer, trace = proc.stdout.strip(), proc.stderr
    except subprocess.TimeoutExpired:
        answer, trace = "", "TIMEOUT"
    elapsed = round(time.time() - started, 1)

    intent, host = "", ""
    match = re.search(r"intent_proposed (\{.*?\})", trace)
    if match:
        try:
            args = json.loads(match.group(1))
            intent = re.sub(r"[^a-z.]", "", args.get("intent", "").lower())
            host = args.get("host", "")
        except json.JSONDecodeError:
            pass
    return answer, intent, host, elapsed


def write_report(name, title, lines):
    os.makedirs(RUNTIME, exist_ok=True)
    path = os.path.join(RUNTIME, name)
    with open(path, "w") as fh:
        fh.write("# %s\n\n" % title)
        fh.write("\n".join(lines) + "\n")
    print("\nreport written to %s" % path)
    return path
