import os
import secrets


SECRET_PATH = os.getenv("SECRET", "/data/secret")


def load_secret() -> bytes:
    if os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "rb") as f:
            return f.read()

    secret = secrets.token_bytes(32)
    with open(SECRET_PATH, "wb") as f:
        f.write(secret)
    return secret
