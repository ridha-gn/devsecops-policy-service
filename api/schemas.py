from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum


# ── Code types ─────────────────────────────────────────────────────────────────
class CodeType(str, Enum):
    TERRAFORM  = "terraform"
    DOCKERFILE = "dockerfile"
    YAML       = "yaml"


class BlockThreshold(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class AnalyzeRequest(BaseModel):
    code_type: CodeType = Field(..., description="Type of infrastructure code")
    content: str = Field(..., description="The actual code content to analyze")
    filename: Optional[str] = Field(None, description="Original filename for reporting")
    block_threshold: BlockThreshold = Field(
        BlockThreshold.LOW,
        description="Minimum severity level to trigger a BLOCK decision"
    )
    diff_only: Optional[str] = Field(
        None,
        description="If provided, only scan lines present in this unified diff"
    )


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Violation(BaseModel):
    rule: str
    severity: Severity
    line: Optional[int] = None
    message: str
    recommendation: Optional[str] = None


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class AnalyzeResponse(BaseModel):
    decision: Decision
    violations: List[Violation] = []
    explanation: str
    scan_time_ms: Optional[int] = None
    filename: Optional[str] = None
    block_threshold: Optional[str] = None
    report_url: Optional[str] = None


class ScanHistoryItem(BaseModel):
    id: int
    timestamp: str
    filename: Optional[str]
    code_type: str
    decision: str
    violations_count: int
    scan_time_ms: int
    block_threshold: str


# ── Auto-Fix Schemas ───────────────────────────────────────────────────────────
class FixRequest(BaseModel):
    code_type: CodeType = Field(..., description="Type of infrastructure code")
    content: str = Field(..., description="The insecure code to fix")


class FixDetail(BaseModel):
    rule_id: str
    line: Optional[int] = None
    description: str
    original: str
    fixed: str


class FixResponse(BaseModel):
    original_code: str
    fixed_code: str
    fixes_applied: List[FixDetail] = []
    total_fixes: int = 0
    diff: Optional[str] = None


# ── RBAC / Auth Schemas ────────────────────────────────────────────────────────
class UserRole(str, Enum):
    DEVELOPER        = "DEVELOPER"
    DEVOPS_ENGINEER  = "DEVOPS_ENGINEER"
    SECURITY_OFFICER = "SECURITY_OFFICER"
    SUPER_ADMIN      = "SUPER_ADMIN"


class LoginRequest(BaseModel):
    username: str = Field(..., example="admin")
    password: str = Field(..., example="admin123")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, example="john_dev")
    password: str = Field(..., min_length=6, example="SecurePass123")
    role: UserRole = Field(UserRole.DEVELOPER, example="DEVELOPER")


class UserOut(BaseModel):
    id: int
    username: str
    role: UserRole
    created_at: str
    created_by: Optional[str] = "system"


class RoleUpdate(BaseModel):
    role: UserRole = Field(..., example="DEVOPS_ENGINEER")
