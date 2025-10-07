# detector.py
import requests
import time
import sqlite3
import re
from pathlib import Path

BASE_VULN = "http://127.0.0.1:5000"  # vulnerable app
BASE_SAFE = "http://127.0.0.1:5001"  # safe app (for mitigation demo)
PAYLOAD_FILE = Path("payloads.txt")
FINDINGS_DB = Path("findings.db")
TIMEOUT = 5  # seconds

SUS_KEYWORDS = re.compile(r"\b(UNION|SELECT|DROP|--|' OR '|\" OR \")\b", re.IGNORECASE)

def init_findings_db():
    if FINDINGS_DB.exists():
        FINDINGS_DB.unlink()
    conn = sqlite3.connect(FINDINGS_DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT,
        payload TEXT,
        status INTEGER,
        resp_len INTEGER,
        error TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );""")
    conn.commit()
    conn.close()

def load_payloads():
    return [line.strip() for line in PAYLOAD_FILE.read_text().splitlines() if line.strip() and not line.strip().startswith("#")]

def probe_login(base_url, payload):
    url = f"{base_url}/login"
    data = {"username": payload, "password": "noop"}
    try:
        r = requests.post(url, data=data, timeout=TIMEOUT)
        return r.status_code, len(r.text), r.text
    except requests.exceptions.RequestException as e:
        return None, None, str(e)

def probe_search(base_url, payload):
    url = f"{base_url}/search"
    params = {"q": payload}
    try:
        r = requests.get(url, params=params, timeout=TIMEOUT)
        return r.status_code, len(r.text), r.text
    except requests.exceptions.RequestException as e:
        return None, None, str(e)

def log_finding(endpoint, payload, status, resp_len, error):
    conn = sqlite3.connect(FINDINGS_DB)
    cur = conn.cursor()
    cur.execute("INSERT INTO findings (endpoint, payload, status, resp_len, error) VALUES (?, ?, ?, ?, ?)",
                (endpoint, payload, status, resp_len, error))
    conn.commit()
    conn.close()

def analyze_response(resp_text):
    # heuristics:
    # 1) visible DB error messages (sqlite error strings)
    # 2) suspicious keywords in response (UNION, SELECT) or SQL fragments
    # 3) unusually large change in response size (handled outside)
    errors = []
    if resp_text is None:
        return errors
    # SQLite error signature often contains "OperationalError" or "sqlite3"
    if "sqlite3" in resp_text.lower() or "operationalerror" in resp_text.lower() or "db error" in resp_text.lower():
        errors.append("db_error_disclosed")
    if SUS_KEYWORDS.search(resp_text):
        errors.append("sql_fragments_in_response")
    return errors

def baseline_measure(base_url):
    # measure baseline response size for benign inputs
    benign_user = ("alice", "alicepass")
    s1 = probe_login(base_url, benign_user[0])
    s2 = probe_search(base_url, "widget")
    return {"login_len": s1[1], "search_len": s2[1]}

def run_tests():
    init_findings_db()
    payloads = load_payloads()
    print(f"Loaded {len(payloads)} payloads.")

    # baseline both apps
    print("Measuring baseline responses for vulnerable app...")
    base_v = baseline_measure(BASE_VULN)
    print("Measuring baseline responses for safe app (mitigation demo)...")
    base_s = baseline_measure(BASE_SAFE)

    for p in payloads:
        # test login
        status, rlen, text = probe_login(BASE_VULN, p)
        errors = analyze_response(text)
        if status is None or errors or (rlen is not None and abs((rlen or 0) - (base_v["login_len"] or 0)) > 50):
            # flag as potential injection
            log_finding("/login", p, status or 0, rlen or 0, ";".join(errors) if errors else "response_size_change")
            print(f"[VULN?] /login payload={p!r} status={status} len={rlen} errors={errors}")
        else:
            print(f"[OK] /login payload={p!r} status={status} len={rlen}")

        # test search
        status, rlen, text = probe_search(BASE_VULN, p)
        errors = analyze_response(text)
        if status is None or errors or (rlen is not None and abs((rlen or 0) - (base_v["search_len"] or 0)) > 80):
            log_finding("/search", p, status or 0, rlen or 0, ";".join(errors) if errors else "response_size_change")
            print(f"[VULN?] /search payload={p!r} status={status} len={rlen} errors={errors}")
        else:
            print(f"[OK] /search payload={p!r} status={status} len={rlen}")

    # Compare with safe app to show mitigation effect for flagged payloads
    print("\n--- Mitigation verification (safe app) ---")
    conn = sqlite3.connect(FINDINGS_DB)
    cur = conn.cursor()
    cur.execute("SELECT endpoint, payload FROM findings")
    rows = cur.fetchall()
    conn.close()

    mitigated = []
    still_problem = []
    for endpoint, payload in rows:
        if endpoint == "/login":
            st, rl, txt = probe_login(BASE_SAFE, payload)
        else:
            st, rl, txt = probe_search(BASE_SAFE, payload)

        errs = analyze_response(txt)
        if errs or st is None:
            still_problem.append((endpoint, payload, st, rl, errs))
        else:
            mitigated.append((endpoint, payload, st, rl))

    print(f"Total flagged on vulnerable app: {len(rows)}")
    print(f"Mitigated on safe app (no errors/diffs): {len(mitigated)}")
    print(f"Still problematic on safe app: {len(still_problem)}")

    # final report summary
    print("\n--- SUMMARY ---")
    print("Flagged findings stored in findings.db table 'findings'.")
    print("Use sqlite3 findings.db 'select * from findings;' to inspect entries.")

if __name__ == "__main__":
    run_tests()
