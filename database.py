import sqlite3
from datetime import datetime

DB_NAME = "s3_detector.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bucket_name TEXT NOT NULL,
            public_access TEXT NOT NULL,
            encryption TEXT NOT NULL,
            versioning TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

    print("Database initialized successfully!")


def save_scan_result(
    bucket_name,
    public_access,
    encryption,
    versioning,
    risk_score,
    risk_level
):
    conn = get_connection()
    cursor = conn.cursor()

    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO scan_results
        (
            bucket_name,
            public_access,
            encryption,
            versioning,
            risk_score,
            risk_level,
            scanned_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        bucket_name,
        public_access,
        encryption,
        versioning,
        risk_score,
        risk_level,
        scanned_at
    ))

    conn.commit()
    conn.close()


def get_all_results():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM scan_results
        ORDER BY id DESC
    """)

    results = cursor.fetchall()

    conn.close()

    return results


if __name__ == "__main__":
    init_db()