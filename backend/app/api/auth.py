"""Registration, login, token refresh, logout, password reset, current user.

Registration creates both a `User` and a brand-new `Org` (the user becomes its
`owner`) in one call — there is no such thing as an account with no org, which
keeps every other endpoint's org-scoping assumption true from row one.
"""
from __future__ import annotations

import logging
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_user
from app.models import Membership, Org, User
from app.schemas_auth import (
    LoginIn,
    LogoutIn,
    MeOut,
    MembershipOut,
    PasswordResetConfirmIn,
    PasswordResetRequestIn,
    RefreshIn,
    RegisterIn,
    TokenOut,
    UserOut,
)
from app.services import auth as auth_svc
from app.services import mail
from app.services.audit import log_action
from app.services.demo_repos import seed_demo_projects

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])

SLUG_RE = re.compile(r"[^a-z0-9-]+")


def _unique_slug(db: Session, name: str) -> str:
    base = SLUG_RE.sub("-", name.lower()).strip("-") or "org"
    slug, n = base, 1
    while db.query(Org).filter(Org.slug == slug).first() is not None:
        n += 1
        slug = f"{base}-{n}"
    return slug


def _tokens(user_id: uuid.UUID) -> TokenOut:
    return TokenOut(
        access_token=auth_svc.create_access_token(user_id),
        refresh_token=auth_svc.create_refresh_token(user_id),
    )


@router.post("/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterIn, db: Session = Depends(get_db)) -> TokenOut:
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status.HTTP_409_CONFLICT, detail="an account with that email already exists")

    user = User(id=uuid.uuid4(), email=payload.email, name=payload.name,
                password_hash=auth_svc.hash_password(payload.password))
    db.add(user)
    db.flush()

    org = Org(id=uuid.uuid4(), name=payload.org_name, slug=_unique_slug(db, payload.org_name))
    db.add(org)
    db.flush()

    db.add(Membership(id=uuid.uuid4(), user_id=user.id, org_id=org.id, role="owner"))
    log_action(db, org_id=org.id, actor=user.email, action="user.register",
               detail=f"registered and created org {org.slug}")
    seed_demo_projects(db, org.id)
    db.commit()
    log.info("registered %s, created org %s", user.email, org.slug)
    return _tokens(user.id)


@router.post("/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)) -> TokenOut:
    user = db.query(User).filter(User.email == payload.email).first()
    if user is None or not auth_svc.verify_password(payload.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="wrong email or password")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="account is disabled")
    return _tokens(user.id)


@router.post("/refresh", response_model=TokenOut)
def refresh(payload: RefreshIn, db: Session = Depends(get_db)) -> TokenOut:
    try:
        claims = auth_svc.decode_token(payload.refresh_token, auth_svc.REFRESH, db)
    except auth_svc.TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    user = db.get(User, uuid.UUID(claims["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="user not found or inactive")
    # Rotate: the old refresh token is spent so a leaked one has a single use.
    auth_svc.revoke(payload.refresh_token, db)
    return _tokens(user.id)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: LogoutIn, db: Session = Depends(get_db)) -> None:
    auth_svc.revoke(payload.refresh_token, db)


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
def request_password_reset(payload: PasswordResetRequestIn, db: Session = Depends(get_db)) -> dict:
    user = db.query(User).filter(User.email == payload.email).first()
    # Same response whether or not the account exists - do not leak enrollment.
    if user is not None:
        from app.config import settings
        token = auth_svc.create_reset_token(user.id)
        link = f"{settings.frontend_url}/reset-password?token={token}"
        mail.send(user.email, "Reset your FANTOM password",
                  f"Reset your password: {link}\nThis link expires in one hour.")
    return {"ok": True, "note": "if that email has an account, a reset link was sent"}


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
def confirm_password_reset(payload: PasswordResetConfirmIn, db: Session = Depends(get_db)) -> None:
    try:
        claims = auth_svc.decode_token(payload.token, auth_svc.RESET, db)
    except auth_svc.TokenError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    user = db.get(User, uuid.UUID(claims["sub"]))
    if user is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="user not found")
    user.password_hash = auth_svc.hash_password(payload.new_password)
    log_action(db, actor=user.email, action="user.password_reset", detail="password reset completed")
    # revoke() commits — it must durably persist immediately as a security action —
    # which also flushes the password change and audit row queued above.
    auth_svc.revoke(payload.token, db)


@router.get("/me", response_model=MeOut)
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> MeOut:
    rows = (
        db.query(Membership, Org)
        .join(Org, Org.id == Membership.org_id)
        .filter(Membership.user_id == user.id)
        .all()
    )
    return MeOut(
        user=UserOut(id=str(user.id), email=user.email, name=user.name,
                     is_active=user.is_active, created_at=user.created_at),
        memberships=[
            MembershipOut(org_id=str(org.id), org_name=org.name, org_slug=org.slug, role=m.role)
            for m, org in rows
        ],
    )
