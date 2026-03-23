"""
Auth Router
FastAPI router for all /api/auth/* endpoints.

POST /api/auth/register  — create account, set httpOnly cookie
POST /api/auth/login     — verify credentials, set httpOnly cookie  (Commit 6)
GET  /api/auth/me        — decode cookie, return current user       (Commit 7)
POST /api/auth/logout    — clear the httpOnly cookie                (Commit 8)
"""

from fastapi import APIRouter, HTTPException, Request, Response

from backend.auth_models import LoginRequest, RegisterRequest, UserResponse, MessageResponse, ProfileUpdateRequest, ChangePasswordRequest
from backend.user_store import create_user, email_exists, get_user_by_email, get_user_by_id, update_user, update_user_password
from backend.auth_utils import create_access_token, decode_access_token, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])

COOKIE_NAME = "cs_token"


def _set_auth_cookie(response: Response, user_id: str) -> None:
    """Sign a JWT and attach it as an httpOnly cookie."""
    token = create_access_token(user_id)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,          # JS cannot read this
        samesite="none",        # CSRF protection
        secure=True,            # production (HTTPS)
        max_age=7 * 24 * 3600,  # 7 days in seconds
        path="/",
    )


# POST /api/auth/register

@router.post("/register", response_model=UserResponse)
def register(body: RegisterRequest, response: Response):
    """
    Register a new user.
    Hashes password with bcrypt, stores user in memory,
    then sets a signed JWT as an httpOnly cookie.
    """
    if not body.username.strip() or len(body.username.strip()) < 3:
        raise HTTPException(status_code=422, detail="Username must be at least 3 characters.")
    if not body.email.strip():
        raise HTTPException(status_code=422, detail="Email is required.")
    if not body.password or len(body.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")
    if email_exists(body.email):
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    user = create_user(
        username=body.username.strip(),
        email=body.email.strip(),
        hashed_password=hash_password(body.password),
    )
    _set_auth_cookie(response, user["id"])
    return UserResponse(id=user["id"], username=user["username"], email=user["email"])


# POST /api/auth/login

@router.post("/login", response_model=UserResponse)
def login(body: LoginRequest, response: Response):
    """
    Authenticate an existing user.
    Looks up by email, verifies bcrypt hash, issues a fresh JWT cookie.
    Uses a generic error message to avoid exposing whether the email exists.
    """
    user = get_user_by_email(body.email)
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    _set_auth_cookie(response, user["id"])
    return UserResponse(id=user["id"], username=user["username"], email=user["email"])


# GET /api/auth/me

@router.get("/me", response_model=UserResponse)
def get_me(request: Request):
    """
    Return the currently authenticated user.
    Reads the JWT from the httpOnly cookie, verifies it,
    then looks up the user in the store by id.
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    user_id = decode_access_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired session. Please sign in again.")

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")

    return UserResponse(id=user["id"], username=user["username"], email=user["email"])


# PUT /api/auth/profile

@router.put("/profile", response_model=UserResponse)
def update_profile(body: ProfileUpdateRequest, request: Request, response: Response):
    """
    Update the currently authenticated user's profile (username and/or email).
    Re-issues the auth cookie after update to keep the session valid.
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    user_id = decode_access_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")

    # Validate inputs
    if body.username is not None and len(body.username.strip()) < 3:
        raise HTTPException(status_code=422, detail="Username must be at least 3 characters.")
    if body.email is not None and not body.email.strip():
        raise HTTPException(status_code=422, detail="Email is required.")

    # Check if new email is already taken by another user
    if body.email is not None:
        existing = get_user_by_email(body.email)
        if existing and existing["id"] != user_id:
            raise HTTPException(status_code=409, detail="An account with this email already exists.")

    updated = update_user(
        user_id=user_id,
        username=body.username.strip() if body.username else None,
        email=body.email.strip() if body.email else None,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="User not found.")

    # Refresh the auth cookie
    _set_auth_cookie(response, updated["id"])

    return UserResponse(id=updated["id"], username=updated["username"], email=updated["email"])


# POST /api/auth/logout

@router.post("/logout", response_model=MessageResponse)
def logout(response: Response):
    """
    Sign the user out by clearing the httpOnly cookie.
    Sets Max-Age=0 so the browser deletes it immediately.
    Frontend JS cannot do this itself — only the server can clear an httpOnly cookie.
    """
    response.delete_cookie(key=COOKIE_NAME, path="/", samesite="lax")
    return MessageResponse(message="Signed out successfully.", success=True)


# PUT /api/auth/change-password

@router.put("/change-password", response_model=MessageResponse)
def change_password(body: ChangePasswordRequest, request: Request, response: Response):
    """
    Allow authenticated users to change their password.
    Requires current password for verification.
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    user_id = decode_access_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if not verify_password(body.current_password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect current password.")

    if not body.new_password or len(body.new_password) < 8:
        raise HTTPException(status_code=422, detail="New password must be at least 8 characters.")

    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="New password cannot be the same as the current password.")

    updated = update_user_password(user_id, hash_password(body.new_password))
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update password.")

    # Re-issue auth cookie
    _set_auth_cookie(response, user_id)

    return MessageResponse(message="Password updated successfully.", success=True)
