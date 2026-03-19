"""
In-Memory User Store
====================
Stores registered users in a plain Python dict for the lifetime of the server.
Keys are lowercased emails for fast login lookup.
"""

import uuid
from typing import Optional, Dict

_users: Dict[str, dict] = {}


def get_user_by_email(email: str) -> Optional[dict]:
    return _users.get(email.lower())


def get_user_by_id(user_id: str) -> Optional[dict]:
    for user in _users.values():
        if user["id"] == user_id:
            return user
    return None


def email_exists(email: str) -> bool:
    return email.lower() in _users


def create_user(username: str, email: str, hashed_password: str) -> dict:
    user = {
        "id":              str(uuid.uuid4()),
        "username":        username,
        "email":           email.lower(),
        "hashed_password": hashed_password,
    }
    _users[email.lower()] = user
    return user
