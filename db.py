# init_db.py
import sqlite3
from pathlib import Path

DB_FILE = Path("playground.db")

def init_db():
    if DB_FILE.exists():
        print("Removing existing DB and recreating.")
        DB_FILE.unlink()

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );
    """)
    cur.execute("""
    CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT,
        price REAL
    );
    """)

    users = [
        ("alice", "alicepass"),
        ("bob", "bobpass"),
        ("carol", "carolpass"),
    ]
    products = [
        ("Red Widget", "Small red widget", 9.99),
        ("Blue Widget", "Large blue widget", 19.99),
        ("Green Gadget", "Green gadget with features", 29.99),
    ]
    cur.executemany("INSERT INTO users (username, password) VALUES (?, ?);", users)
    cur.executemany("INSERT INTO products (name, description, price) VALUES (?, ?, ?);", products)

    conn.commit()
    conn.close()
    print("Initialized playground.db with sample users and products.")

if __name__ == "__main__":
    init_db()
