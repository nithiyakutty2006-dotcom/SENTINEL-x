import hashlib
import hmac


def hash_password(password: str) -> str:
    """Hash passwords using the existing SENTINEL-X password format."""
    salt = "SENTINEL_X_SOC_SECRET_SALT_2026"
    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()


def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a stored hash or migrate-compatible legacy plaintext password."""
    if stored_password == provided_password:
        return True
    return hmac.compare_digest(stored_password, hash_password(provided_password))
