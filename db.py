import sqlite3

DB_NAME = "mydb.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    conn = get_connection()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        encrypted_text TEXT NOT NULL,
        nonce TEXT NOT NULL,
        tag TEXT NOT NULL
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS search_index (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        record_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        FOREIGN KEY(record_id) REFERENCES records(id)
    )
    """)

    conn.commit()
    conn.close()