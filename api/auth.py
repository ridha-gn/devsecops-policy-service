"""
api/auth.py
-----------
JWT authentication & Role-Based Access Control (RBAC) engine.

Roles (lowest → highest privilege):
  DEVELOPER        – scan code, view own history
  DEVOPS_ENGINEER  – + auto-fix, full history, metrics, PDF reports
  SECURITY_OFFICER – + Prometheus metrics, user listing
  SUPER_ADMIN      – full access + user management
"""

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import bcrypt as _bcrypt
from enum import Enum

SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY", "devsecops-policy-service-secret-key-CHANGE-IN-PRODUCTION-2024"
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "8"))


bearer_scheme = HTTPBearer(auto_error=False)


class UserRole(str, Enum):
    DEVELOPER = "DEVELOPER"
    DEVOPS_ENGINEER = "DEVOPS_ENGINEER"
    SECURITY_OFFICER = "SECURITY_OFFICER"
    SUPER_ADMIN = "SUPER_ADMIN"


ROLE_DISPLAY = {
    UserRole.DEVELOPER: "Developer",
    UserRole.DEVOPS_ENGINEER: "DevOps Engineer",
    UserRole.SECURITY_OFFICER: "Security Officer",
    UserRole.SUPER_ADMIN: "Super Admin",
}


def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    """Decode the Bearer token and return the current user dict."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = _decode_token(credentials.credentials)
    username = payload.get("sub")
    role = payload.get("role")
    user_id = payload.get("user_id")
    if not username or not role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload.",
        )
    return {"username": username, "role": UserRole(role), "user_id": user_id}


def require_roles(*allowed_roles: UserRole):
    """
    Dependency factory.  Usage:
        @router.get("/secret", dependencies=[Depends(require_roles(UserRole.SUPER_ADMIN))])
    or as a parameter:
        current = Depends(require_roles(UserRole.DEVOPS_ENGINEER, UserRole.SUPER_ADMIN))
    """

    async def _checker(
        current_user: dict = Depends(get_current_user),
    ) -> dict:
        if current_user["role"] not in allowed_roles:
            role_names = [r.value for r in allowed_roles]
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Access denied. Your role '{current_user['role'].value}' "
                    f"does not have permission for this action. "
                    f"Required: {role_names}"
                ),
            )
        return current_user

    return _checker
