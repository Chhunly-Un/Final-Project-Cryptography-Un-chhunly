# db.py
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path.home() / ".crypto_guard_plus" / "events.db"

def _ensure_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        action TEXT,
        details TEXT
    )
    """)
    conn.commit()
    conn.close()

def log_event(action, details=""):
    _ensure_db()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO events (ts, action, details) VALUES (?, ?, ?)",
                (datetime.utcnow().isoformat(), action, details))
    conn.commit()
    conn.close()
