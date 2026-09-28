"""Auth and tenancy dependencies.

`get_current_user` is the only thing that reads the bearer token. Everything
else builds on it: `get_current_org` resolves the caller's membership for an
`X-Org-Id` header (defaulting to their only org when they have exactly one),
and `require_role` gates a route to a subset of roles within that org.
"""
from __future__ import annotations

import uuid

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Membership, Org, User
from app.services import auth as auth_svc

bearer = HTTPBearer(auto_error=False)


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    try:
        payload = auth_svc.decode_token(creds.credentials, auth_svc.ACCESS, db)
    except auth_svc.TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    user = db.get(User, uuid.UUID(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="user not found or inactive")
    return user


def get_current_org(
    x_org_id: str | None = Header(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> tuple[Org, Membership]:
    """Resolves the org this request acts on, plus the caller's membership in it."""
    q = db.query(Membership).filter(Membership.user_id == user.id)
    if x_org_id:
        try:
            org_uuid = uuid.UUID(x_org_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="X-Org-Id is not a valid id") from exc
        membership = q.filter(Membership.org_id == org_uuid).first()
        if membership is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="not a member of that org")
    else:
        memberships = q.all()
        if not memberships:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="not a member of any org")
        if len(memberships) > 1:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail="member of multiple orgs - pass X-Org-Id to disambiguate",
            )
        membership = memberships[0]
    org = db.get(Org, membership.org_id)
    return org, membership


def require_role(*roles: str):
    """Dependency factory: `Depends(require_role('owner', 'admin'))`."""
    def _check(ctx: tuple[Org, Membership] = Depends(get_current_org)) -> tuple[Org, Membership]:
        org, membership = ctx
        if membership.role not in roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"requires role in {roles}, caller has '{membership.role}'",
            )
        return org, membership
    return _check
