# app_safe.py
from flask import Flask, request, jsonify
import sqlite3

DB = "playground.db"
app = Flask(__name__)

def query_db_param(sql, params=()):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return rows

@app.route("/")
def index():
    return (
        "<h2>SQLi Playground (Safe)</h2>"
        "<p>Endpoints: /login (POST username,password), /search?q=...</p>"
    )

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    sql = "SELECT id, username FROM users WHERE username = ? AND password = ?;"
    try:
        rows = query_db_param(sql, (username, password))
    except Exception as e:
        return "DB Error", 500

    if rows:
        return jsonify({"status": "ok", "user": rows[0][1]})
    else:
        return jsonify({"status": "fail"}), 401

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # parameterized query with wildcards composed in Python
    like_q = f"%{q}%"
    sql = "SELECT id, name, description FROM products WHERE name LIKE ? OR description LIKE ?;"
    try:
        rows = query_db_param(sql, (like_q, like_q))
    except Exception as e:
        return "DB Error", 500

    results = [{"id": r[0], "name": r[1], "description": r[2]} for r in rows]
    return jsonify({"count": len(results), "results": results})

if __name__ == "__main__":
    app.run(port=5001, debug=True)
