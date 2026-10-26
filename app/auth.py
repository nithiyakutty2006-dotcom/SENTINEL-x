import hashlib
import secrets
import time

from app.database import get_db_connection, audit_log_event
from app.passwords import hash_password, verify_password

SESSION_COOKIE_NAME = "sentinel_session"
SESSION_TTL_SECONDS = 12 * 60 * 60


class AuthenticationConfigurationError(Exception):
    """Raised when the database has no configured login accounts."""


def authenticate_user(username: str, password: str):
    conn = get_db_connection()
    row = conn.execute("""
        SELECT username, password, role
        FROM users
        WHERE username=?
    """, (username,)).fetchone()
    
    if row is None and conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None:
        raise AuthenticationConfigurationError(
            "No login accounts are configured. Set SENTINEL_ADMIN_USERNAME and "
            "SENTINEL_ADMIN_PASSWORD, then restart the application with an empty "
            "users table to initialize the admin account."
        )

    if row and verify_password(row["password"], password):
        # Auto-migrate plaintext demo passwords to hashed passwords on successful login
        if row["password"] == password:
            hashed = hash_password(password)
            conn.execute("UPDATE users SET password=? WHERE username=?", (hashed, username))
            conn.commit()
            
        audit_log_event(username, "Successful web authentication")
        return {"username": row["username"], "role": row["role"]}
    
    return None

def check_permission(user_role: str, allowed_roles: list) -> bool:
    """
    Check if the user's role is in the list of allowed roles.
    ADMIN has access to all actions.
    """
    if not user_role:
        return False
    if user_role == "ADMIN":
        return True
    return user_role in allowed_roles


def create_web_session(username: str):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    now = time.time()
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM web_sessions WHERE expires_at <= ?", (now,))
        conn.execute(
            "INSERT INTO web_sessions(session_hash, username, expires_at) VALUES(?,?,?)",
            (token_hash, username, now + SESSION_TTL_SECONDS),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def resolve_web_session(token: str):
    if not token or len(token) > 256:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = time.time()
    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT u.username, u.role, s.expires_at
            FROM web_sessions s
            JOIN users u ON u.username=s.username
            WHERE s.session_hash=?
            """,
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        if row["expires_at"] <= now:
            conn.execute("DELETE FROM web_sessions WHERE session_hash=?", (token_hash,))
            conn.commit()
            return None
        return {"username": row["username"], "role": row["role"]}
    finally:
        conn.close()


def revoke_web_session(token: str):
    if not token or len(token) > 256:
        return
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM web_sessions WHERE session_hash=?", (token_hash,))
        conn.commit()
    finally:
        conn.close()
