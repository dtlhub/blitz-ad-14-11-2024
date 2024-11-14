import sqlite3
from sqlite3 import DatabaseError
import os


DB_PATH = os.getenv("DB", "/data/bouquets.db")


def connection_manager(query, *args):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=20)
        cur = conn.cursor()
        cur.execute(query, (args))
        res = cur.fetchall()
        conn.commit()
        conn.close()
        return res
    except DatabaseError:
        conn.rollback()
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    with open("init.sql", mode="r") as f:
        cur.executescript(f.read())
    conn.commit()
    conn.close()
