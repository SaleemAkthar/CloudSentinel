"""
Auth Utilities
==============
JWT creation / verification and bcrypt password helpers.

JWT payload: { "sub": "<user_id>", "exp": <unix_timestamp> }

Override SECRET_KEY via AUTH_SECRET_KEY env var before deploying.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

# Config

SECRET_KEY: str = os.environ.get(
    "AUTH_SECRET_KEY",
    "change-me-in-production-use-a-long-random-string"
)
ALGORITHM = "HS256"
TOKEN_EXPIRE_DAYS = 7

# Bcrypt

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)



# JWT

def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRE_DAYS)
    return jwt.encode({"sub": user_id, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[str]:
    """Returns user_id on success, None if invalid or expired."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None
