"""
api/users.py
------------
User management router + authentication endpoint.

Endpoints:
  POST /auth/login              – public, returns JWT
  POST /users                   – Super Admin only
  GET  /users                   – Security Officer + Super Admin
  PATCH /users/{id}/role        – Super Admin only
  DELETE /users/{id}            – Super Admin only
  GET  /users/me                – any authenticated user
"""
import os
import sqlite3
from datetime import datetime
from typing import List

from fastapi import APIRouter, HTTPException, Depends, status

from api.auth import (
    UserRole, hash_password, verify_password,
    create_access_token, require_roles, get_current_user,
)
from api.schemas import (
    LoginRequest, TokenResponse,
    UserCreate, UserOut, RoleUpdate,
)

router = APIRouter()

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'scans.db')


# ── DB helpers ────────────────────────────────────────────────────────────────

def _get_by_username(username: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def _get_by_id(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# ── Authentication ────────────────────────────────────────────────────────────

@router.post(
    "/auth/login",
    response_model=TokenResponse,
    tags=["🔑 Authentication"],
    summary="Login and receive a JWT access token",
)
async def login(request: LoginRequest):
    """
    Authenticate with username + password.
    Returns a JWT token valid for 8 hours (configurable via JWT_EXPIRE_HOURS env var).
    """
    user = _get_by_username(request.username)
    if not user or not verify_password(request.password, user["hashed_pw"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token({
        "sub":     user["username"],
        "role":    user["role"],
        "user_id": user["id"],
    })
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user["role"],
        username=user["username"],
    )


# ── Current user info ─────────────────────────────────────────────────────────

@router.get(
    "/users/me",
    response_model=UserOut,
    tags=["👤 User Management"],
    summary="Get your own profile",
)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Returns the currently authenticated user's profile."""
    user = _get_by_username(current_user["username"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return UserOut(
        id=user["id"],
        username=user["username"],
        role=UserRole(user["role"]),
        created_at=user["created_at"],
        created_by=user.get("created_by", "system"),
    )


# ── User Management (Admin) ───────────────────────────────────────────────────

@router.post(
    "/users",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    tags=["👤 User Management"],
    summary="Create a new user (Super Admin only)",
)
async def create_user(
    payload: UserCreate,
    current: dict = Depends(require_roles(UserRole.SUPER_ADMIN)),
):
    """Create a new user and assign them a role. **Super Admin only.**"""
    if _get_by_username(payload.username):
        raise HTTPException(status_code=409, detail=f"Username '{payload.username}' already exists.")

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(
        "INSERT INTO users (username, hashed_pw, role, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
        (payload.username, hash_password(payload.password),
         payload.role.value, now, current["username"]),
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return UserOut(
        id=user_id,
        username=payload.username,
        role=payload.role,
        created_at=now,
        created_by=current["username"],
    )


@router.get(
    "/users",
    response_model=List[UserOut],
    tags=["👤 User Management"],
    summary="List all users (Security Officer / Super Admin)",
)
async def list_users(
    _: dict = Depends(require_roles(UserRole.SECURITY_OFFICER, UserRole.SUPER_ADMIN)),
):
    """List all registered users with their roles."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, username, role, created_at, created_by FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return [
        UserOut(
            id=r["id"],
            username=r["username"],
            role=UserRole(r["role"]),
            created_at=r["created_at"] or "N/A",
            created_by=dict(r).get("created_by") or "system",
        )
        for r in rows
    ]


@router.patch(
    "/users/{user_id}/role",
    response_model=UserOut,
    tags=["👤 User Management"],
    summary="Change a user's role (Super Admin only)",
)
async def update_role(
    user_id: int,
    payload: RoleUpdate,
    current: dict = Depends(require_roles(UserRole.SUPER_ADMIN)),
):
    """Reassign the role of any user. **Super Admin only.**"""
    user = _get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user["username"] == "admin":
        raise HTTPException(status_code=403, detail="Cannot modify the root admin account.")

    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (payload.role.value, user_id))
    conn.commit()
    conn.close()

    return UserOut(
        id=user_id,
        username=user["username"],
        role=payload.role,
        created_at=user["created_at"],
        created_by=user.get("created_by", "system"),
    )


@router.delete(
    "/users/{user_id}",
    tags=["👤 User Management"],
    summary="Delete a user (Super Admin only)",
)
async def delete_user(
    user_id: int,
    _: dict = Depends(require_roles(UserRole.SUPER_ADMIN)),
):
    """Permanently delete a user account. **Super Admin only.**"""
    user = _get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user["username"] == "admin":
        raise HTTPException(status_code=403, detail="Cannot delete the root admin account.")

    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    return {"message": f"User '{user['username']}' deleted successfully."}
