"""
In-Memory User Store (Persisted to JSON)
========================================
Stores registered users in a local JSON file to survive server reloads.
Keys are lowercased emails for fast login lookup.
"""

import os
import json
import uuid
from typing import Optional, Dict

DB_FILE = os.path.join(os.path.dirname(__file__), "users.json")

def _load_users() -> Dict[str, dict]:
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def _save_users(users: Dict[str, dict]):
    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=2)

_users: Dict[str, dict] = _load_users()

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
    _save_users(_users)
    return user


def update_user(user_id: str, username: Optional[str] = None, email: Optional[str] = None) -> Optional[dict]:
    """Update a user's username and/or email by user_id. Persists to JSON."""
    # Find the user by id
    old_key = None
    user = None
    for key, u in _users.items():
        if u["id"] == user_id:
            old_key = key
            user = u
            break
    if not user:
        return None

    if username is not None:
        user["username"] = username

    if email is not None:
        new_email = email.lower()
        # If email changed, re-key the dict
        if new_email != old_key:
            # Check if the new email is already taken by someone else
            if new_email in _users:
                return None
            del _users[old_key]
            user["email"] = new_email
            _users[new_email] = user
        else:
            user["email"] = new_email

    _save_users(_users)
    return user

