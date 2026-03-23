"""
Auth Pydantic Models
Request bodies and response shapes for all /api/auth/* endpoints.
"""

from pydantic import BaseModel


# Request bodies

class RegisterRequest(BaseModel):
    """Body sent by the Signup form."""
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    """Body sent by the Signin form."""
    email: str
    password: str


# Response shapes

class UserResponse(BaseModel):
    """Safe user object returned to the frontend (no password hash)."""
    id: str
    username: str
    email: str
    created_at: str | None = None


class MessageResponse(BaseModel):
    """Generic success / error message."""
    message: str
    success: bool = True


class ProfileUpdateRequest(BaseModel):
    """Body sent by the Profile edit form."""
    username: str | None = None
    email: str | None = None

