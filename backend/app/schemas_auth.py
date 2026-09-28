"""Request/response shapes for auth, orgs, membership, teams, and audit."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.models.tables import MEMBERSHIP_ROLES


# ------------------------------------------------------------------- auth --
class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=200)
    name: str = Field(..., min_length=1, max_length=200)
    org_name: str = Field(..., min_length=1, max_length=200,
                          description="Creates a new org with this user as owner")


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class RefreshIn(BaseModel):
    refresh_token: str


class LogoutIn(BaseModel):
    refresh_token: str


class PasswordResetRequestIn(BaseModel):
    email: EmailStr


class PasswordResetConfirmIn(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=200)


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    is_active: bool
    created_at: datetime


class MembershipOut(BaseModel):
    org_id: str
    org_name: str
    org_slug: str
    role: str


class MeOut(BaseModel):
    user: UserOut
    memberships: list[MembershipOut]


# -------------------------------------------------------------------- org --
class OrgOut(BaseModel):
    id: str
    name: str
    slug: str
    created_at: datetime


class OrgCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)


class InvitationCreate(BaseModel):
    email: EmailStr
    role: str = Field(..., description=f"One of {', '.join(MEMBERSHIP_ROLES)}")


class InvitationOut(BaseModel):
    id: str
    org_id: str
    email: str
    role: str
    accepted_at: datetime | None
    expires_at: datetime
    created_at: datetime


class InvitationAccept(BaseModel):
    token: str
    password: str | None = Field(None, min_length=8, max_length=200,
                                 description="Required only if this email has no account yet")
    name: str | None = Field(None, max_length=200)


class MemberOut(BaseModel):
    user_id: str
    email: str
    name: str
    role: str
    joined_at: datetime


class MemberRoleUpdate(BaseModel):
    role: str = Field(..., description=f"One of {', '.join(MEMBERSHIP_ROLES)}")


class TeamCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)


class TeamOut(BaseModel):
    id: str
    name: str
    member_ids: list[str]
    created_at: datetime


# ------------------------------------------------------------------ audit --
class AuditLogOut(BaseModel):
    id: int
    ts: datetime
    org_id: str | None
    project_id: str | None
    actor: str
    action: str
    detail: str | None
