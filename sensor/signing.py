import hashlib
import hmac


def sign_sensor_request(secret, timestamp, nonce, body):
    message = str(timestamp).encode("ascii") + b"\n" + nonce.encode("ascii") + b"\n" + body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
