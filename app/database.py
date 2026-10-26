import sqlite3
import os
import logging
from datetime import datetime
from app.paths import data_path
from app.passwords import hash_password

DB_PATH = str(data_path("sentinel_x_v2.db"))

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

DB = get_db_connection()

def now_string():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run_migrations(conn):
    cursor = conn.cursor()
    
    # Helper to check if column exists in table
    def column_exists(table, column):
        cursor.execute(f"PRAGMA table_info({table})")
        columns = [row[1] for row in cursor.fetchall()]
        return column in columns

    # 1. Events Table Migrations
    if not column_exists("events", "ai_score"):
        cursor.execute("ALTER TABLE events ADD COLUMN ai_score REAL DEFAULT 0.0")
    if not column_exists("events", "source_type"):
        cursor.execute("ALTER TABLE events ADD COLUMN source_type TEXT DEFAULT 'REAL'")
    if not column_exists("events", "rule_score"):
        cursor.execute("ALTER TABLE events ADD COLUMN rule_score REAL DEFAULT 0.0")
    if not column_exists("events", "baseline_score"):
        cursor.execute("ALTER TABLE events ADD COLUMN baseline_score REAL DEFAULT 0.0")
    if not column_exists("events", "factors"):
        cursor.execute("ALTER TABLE events ADD COLUMN factors TEXT DEFAULT ''")

    # 2. Alerts Table Migrations
    if not column_exists("alerts", "source_type"):
        cursor.execute("ALTER TABLE alerts ADD COLUMN source_type TEXT DEFAULT 'REAL'")

    # 3. Incidents Table Migrations
    if not column_exists("incidents", "source_type"):
        cursor.execute("ALTER TABLE incidents ADD COLUMN source_type TEXT DEFAULT 'REAL'")

    for column, definition in (
        ("source_port", "INTEGER DEFAULT 0"),
        ("bytes", "INTEGER DEFAULT 0"),
        ("flow_id", "TEXT"),
        ("sensor_id", "TEXT"),
        ("event_id", "TEXT"),
        ("connection_state", "TEXT"),
        ("endpoint_mode", "TEXT"),
    ):
        if not column_exists("events", column):
            cursor.execute(f"ALTER TABLE events ADD COLUMN {column} {definition}")

    if column_exists("sensors", "sensor_id"):
        for column, definition in (
            ("last_upload_epoch", "REAL"),
            ("last_upload_error", "TEXT"),
        ):
            if not column_exists("sensors", column):
                cursor.execute(f"ALTER TABLE sensors ADD COLUMN {column} {definition}")

    conn.commit()

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        device TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        port INTEGER,
        protocol TEXT,
        packets INTEGER,
        traffic REAL,
        connections INTEGER,
        unknown INTEGER,
        risk INTEGER,
        severity TEXT,
        ai_score REAL DEFAULT 0.0,
        rule_score REAL DEFAULT 0.0,
        baseline_score REAL DEFAULT 0.0,
        factors TEXT DEFAULT '',
        source_type TEXT DEFAULT 'REAL'
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        device TEXT,
        risk INTEGER,
        severity TEXT,
        status TEXT,
        description TEXT,
        source_type TEXT DEFAULT 'REAL'
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        username TEXT,
        action TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        device TEXT,
        risk INTEGER,
        severity TEXT,
        channel TEXT,
        status TEXT,
        source_type TEXT DEFAULT 'REAL'
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings(
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password TEXT,
        role TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device_baseline(
        device TEXT PRIMARY KEY,
        avg_packets REAL,
        avg_traffic REAL,
        avg_connections REAL,
        samples INTEGER,
        last_seen TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS model_metrics(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        training_date TEXT,
        samples INTEGER,
        loss REAL,
        val_loss REAL,
        threshold REAL,
        status TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS model_registry(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version TEXT,
        model_type TEXT,
        architecture TEXT,
        training_date TEXT,
        samples INTEGER,
        loss REAL,
        val_loss REAL,
        threshold REAL,
        status TEXT,
        is_active INTEGER DEFAULT 1
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS datasets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        upload_date TEXT,
        samples INTEGER,
        source_type TEXT,
        status TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS model_evaluations(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evaluation_date TEXT,
        model_version TEXT,
        accuracy REAL,
        precision_score REAL,
        recall_score REAL,
        f1_score REAL,
        mse_loss REAL,
        status TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sensors(
        sensor_id TEXT PRIMARY KEY,
        last_heartbeat_epoch REAL NOT NULL,
        last_event TEXT,
        last_upload_epoch REAL,
        last_upload_error TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sensor_nonces(
        sensor_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        created_at REAL NOT NULL,
        PRIMARY KEY(sensor_id, nonce)
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sensor_requests(
        sensor_id TEXT NOT NULL,
        requested_at REAL NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS web_sessions(
        session_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        expires_at REAL NOT NULL
    )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_web_sessions_expiry
        ON web_sessions(expires_at)
    """)

    conn.commit()

    # Run safe column additions
    run_migrations(conn)
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_events_sensor_event
        ON events(sensor_id, event_id)
    """)

    # Bootstrap configured users only; never create public demo credentials.
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        configured_users = [
            ("SENTINEL_ADMIN_USERNAME", "SENTINEL_ADMIN_PASSWORD", "admin", "ADMIN"),
            ("SENTINEL_ANALYST_USERNAME", "SENTINEL_ANALYST_PASSWORD", "analyst", "ANALYST"),
            ("SENTINEL_VIEWER_USERNAME", "SENTINEL_VIEWER_PASSWORD", "viewer", "VIEWER"),
        ]
        bootstrap_users = []
        for username_key, password_key, default_username, role in configured_users:
            username = os.environ.get(username_key)
            password = os.environ.get(password_key)
            if username and not password:
                raise RuntimeError(
                    f"Both {username_key} and {password_key} must be configured together."
                )
            if password:
                bootstrap_users.append(
                    (username or default_username, hash_password(password), role)
                )

        if not any(role == "ADMIN" for _, _, role in bootstrap_users):
            message = (
                "No users are configured for the empty database. Set "
                "SENTINEL_ADMIN_PASSWORD (and optionally analyst/viewer credentials) "
                "before starting SENTINEL-X."
            )
            if os.environ.get("RENDER"):
                raise RuntimeError(message)
            logging.warning(message)

        for username, password_hash, role in bootstrap_users:
            cursor.execute("""
            INSERT OR IGNORE INTO users(username, password, role)
            VALUES(?,?,?)
            """, (username, password_hash, role))

    # Seed default settings
    default_settings = [
        ("critical_threshold", "80"),
        ("high_threshold", "60"),
        ("monitor_interval", "1.5"),
        ("ml_enabled", "1")
    ]
    for key, value in default_settings:
        cursor.execute("""
        INSERT OR IGNORE INTO settings(key, value)
        VALUES(?,?)
        """, (key, value))

    conn.commit()

def get_setting(key, default):
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if row is None or str(row["value"]).strip() == "":
            return str(default)
        return str(row["value"])
    except Exception:
        return str(default)

def set_setting(key, value):
    conn = get_db_connection()
    conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)", (key, str(value)))
    conn.commit()

def audit_log_event(username, action):
    conn = get_db_connection()
    conn.execute("INSERT INTO audit_log(timestamp, username, action) VALUES(?,?,?)", (now_string(), username, action))
    conn.commit()

# Run initialization
init_db()
