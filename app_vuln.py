# app_vuln.py
from flask import Flask, request, jsonify
import sqlite3

DB = "playground.db"
app = Flask(__name__)

def query_db(sql):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # purposefully not using parameterized queries (vulnerable)
    cur.execute(sql)
    rows = cur.fetchall()
    conn.close()
    return rows

@app.route("/")
def index():
    return (
        "<h2>SQLi Playground (Vulnerable)</h2>"
        "<p>Endpoints: /login (POST username,password), /search?q=...</p>"
    )

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABLE: direct string interpolation
    sql = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}';"
    try:
        rows = query_db(sql)
    except Exception as e:
        # intentionally show DB error for detection learning
        return f"DB Error: {e}", 500

    if rows:
        return jsonify({"status": "ok", "user": rows[0][1]})
    else:
        return jsonify({"status": "fail"}), 401

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: direct interpolation into LIKE clause
    sql = f"SELECT id, name, description FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%';"
    try:
        rows = query_db(sql)
    except Exception as e:
        return f"DB Error: {e}", 500

    results = [{"id": r[0], "name": r[1], "description": r[2]} for r in rows]
    return jsonify({"count": len(results), "results": results})

if __name__ == "__main__":
    app.run(port=5000, debug=True)
