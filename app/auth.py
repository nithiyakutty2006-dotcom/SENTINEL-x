from app.database import get_db_connection, audit_log_event
from app.passwords import hash_password, verify_password


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
