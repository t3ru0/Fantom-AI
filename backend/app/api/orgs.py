"""Organizations, membership, invitations, teams.

Every route resolves the acting org through `get_current_org` (an `X-Org-Id`
header, or the caller's one-and-only org). Membership mutations are gated by
`require_role`: only `owner`/`admin` can invite, change a role, or remove a
member; a member can always leave on their own.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_org, get_current_user, require_role
from app.models import Invitation, Membership, Org, Team, TeamMembership, User
from app.models.tables import MEMBERSHIP_ROLES
from app.schemas_auth import (
    InvitationAccept,
    InvitationCreate,
    InvitationOut,
    MemberOut,
    MemberRoleUpdate,
    OrgCreate,
    OrgOut,
    TeamCreate,
    TeamOut,
    TokenOut,
)
from app.services import auth as auth_svc
from app.services import mail
from app.services.audit import log_action

router = APIRouter(prefix="/api", tags=["orgs"])


def _org_out(org: Org) -> OrgOut:
    return OrgOut(id=str(org.id), name=org.name, slug=org.slug, created_at=org.created_at)


@router.post("/orgs", response_model=OrgOut, status_code=status.HTTP_201_CREATED)
def create_org(payload: OrgCreate, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)) -> OrgOut:
    import re
    slug = re.sub(r"[^a-z0-9-]+", "-", payload.name.lower()).strip("-") or "org"
    base, n = slug, 1
    while db.query(Org).filter(Org.slug == slug).first():
        n += 1
        slug = f"{base}-{n}"
    org = Org(id=uuid.uuid4(), name=payload.name, slug=slug)
    db.add(org)
    db.flush()
    db.add(Membership(id=uuid.uuid4(), user_id=user.id, org_id=org.id, role="owner"))
    log_action(db, org_id=org.id, actor=user.email, action="org.create", detail=org.slug)
    db.commit()
    return _org_out(org)


@router.get("/orgs/current", response_model=OrgOut)
def current_org(ctx: tuple[Org, Membership] = Depends(get_current_org)) -> OrgOut:
    org, _ = ctx
    return _org_out(org)


# ---------------------------------------------------------------- members --
@router.get("/orgs/current/members", response_model=list[MemberOut])
def list_members(ctx: tuple[Org, Membership] = Depends(get_current_org),
                  db: Session = Depends(get_db)) -> list[MemberOut]:
    org, _ = ctx
    rows = (
        db.query(Membership, User)
        .join(User, User.id == Membership.user_id)
        .filter(Membership.org_id == org.id)
        .all()
    )
    return [MemberOut(user_id=str(u.id), email=u.email, name=u.name, role=m.role, joined_at=m.created_at)
            for m, u in rows]


@router.put("/orgs/current/members/{user_id}", response_model=MemberOut)
def update_member_role(user_id: uuid.UUID, payload: MemberRoleUpdate,
                        ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin")),
                        db: Session = Depends(get_db)) -> MemberOut:
    org, actor = ctx
    if payload.role not in MEMBERSHIP_ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"role must be one of {MEMBERSHIP_ROLES}")
    m = db.query(Membership).filter(Membership.org_id == org.id, Membership.user_id == user_id).first()
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="not a member of this org")
    m.role = payload.role
    log_action(db, org_id=org.id, action="member.role_change", detail=f"{user_id} -> {payload.role}")
    db.commit()
    user = db.get(User, user_id)
    return MemberOut(user_id=str(user_id), email=user.email, name=user.name, role=m.role, joined_at=m.created_at)


@router.delete("/orgs/current/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(user_id: uuid.UUID,
                   ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin")),
                   db: Session = Depends(get_db)) -> None:
    org, actor = ctx
    m = db.query(Membership).filter(Membership.org_id == org.id, Membership.user_id == user_id).first()
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="not a member of this org")
    db.delete(m)
    log_action(db, org_id=org.id, action="member.remove", detail=str(user_id))
    db.commit()


# ------------------------------------------------------------- invitations --
@router.post("/orgs/current/invitations", response_model=InvitationOut, status_code=status.HTTP_201_CREATED)
def create_invitation(payload: InvitationCreate,
                       ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin")),
                       db: Session = Depends(get_db)) -> InvitationOut:
    org, actor = ctx
    if payload.role not in MEMBERSHIP_ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"role must be one of {MEMBERSHIP_ROLES}")
    inv = Invitation(
        id=uuid.uuid4(), org_id=org.id, email=payload.email, role=payload.role,
        token=secrets.token_urlsafe(32), invited_by=actor.user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(inv)
    log_action(db, org_id=org.id, action="invitation.create", detail=payload.email)
    db.commit()

    from app.config import settings
    link = f"{settings.frontend_url}/accept-invite?token={inv.token}"
    mail.send(payload.email, f"You're invited to {org.name} on FANTOM",
              f"Join {org.name}: {link}\nThis invitation expires in 7 days.")
    return InvitationOut(id=str(inv.id), org_id=str(org.id), email=inv.email, role=inv.role,
                          accepted_at=inv.accepted_at, expires_at=inv.expires_at, created_at=inv.created_at)


@router.get("/orgs/current/invitations", response_model=list[InvitationOut])
def list_invitations(ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin")),
                      db: Session = Depends(get_db)) -> list[InvitationOut]:
    org, _ = ctx
    rows = db.query(Invitation).filter(Invitation.org_id == org.id).order_by(Invitation.created_at.desc()).all()
    return [InvitationOut(id=str(i.id), org_id=str(i.org_id), email=i.email, role=i.role,
                          accepted_at=i.accepted_at, expires_at=i.expires_at, created_at=i.created_at)
            for i in rows]


@router.post("/invitations/accept", response_model=TokenOut)
def accept_invitation(payload: InvitationAccept, db: Session = Depends(get_db)) -> TokenOut:
    inv = db.query(Invitation).filter(Invitation.token == payload.token).first()
    if inv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="invitation not found")
    if inv.accepted_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="invitation already accepted")
    if inv.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_410_GONE, detail="invitation has expired")

    user = db.query(User).filter(User.email == inv.email).first()
    if user is None:
        if not payload.password or not payload.name:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail="this email has no account yet - name and password are required")
        user = User(id=uuid.uuid4(), email=inv.email, name=payload.name,
                    password_hash=auth_svc.hash_password(payload.password))
        db.add(user)
        db.flush()

    existing = db.query(Membership).filter(Membership.org_id == inv.org_id, Membership.user_id == user.id).first()
    if existing is None:
        db.add(Membership(id=uuid.uuid4(), user_id=user.id, org_id=inv.org_id, role=inv.role))
    inv.accepted_at = datetime.now(timezone.utc)
    log_action(db, org_id=inv.org_id, actor=user.email, action="invitation.accept")
    db.commit()
    return TokenOut(access_token=auth_svc.create_access_token(user.id),
                     refresh_token=auth_svc.create_refresh_token(user.id))


# ------------------------------------------------------------------- teams --
@router.post("/orgs/current/teams", response_model=TeamOut, status_code=status.HTTP_201_CREATED)
def create_team(payload: TeamCreate, ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin")),
                 db: Session = Depends(get_db)) -> TeamOut:
    org, _ = ctx
    if db.query(Team).filter(Team.org_id == org.id, Team.name == payload.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, detail="a team with that name already exists")
    team = Team(id=uuid.uuid4(), org_id=org.id, name=payload.name)
    db.add(team)
    log_action(db, org_id=org.id, action="team.create", detail=payload.name)
    db.commit()
    return TeamOut(id=str(team.id), name=team.name, member_ids=[], created_at=team.created_at)


@router.get("/orgs/current/teams", response_model=list[TeamOut])
def list_teams(ctx: tuple[Org, Membership] = Depends(get_current_org), db: Session = Depends(get_db)) -> list[TeamOut]:
    org, _ = ctx
    teams = db.query(Team).filter(Team.org_id == org.id).all()
    out = []
    for t in teams:
        member_ids = [str(r.user_id) for r in db.query(TeamMembership).filter(TeamMembership.team_id == t.id)]
        out.append(TeamOut(id=str(t.id), name=t.name, member_ids=member_ids, created_at=t.created_at))
    return out


@router.put("/orgs/current/teams/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def add_team_member(team_id: uuid.UUID, user_id: uuid.UUID,
                     ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin")),
                     db: Session = Depends(get_db)) -> None:
    org, _ = ctx
    team = db.get(Team, team_id)
    if team is None or team.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="team not found")
    if not db.query(Membership).filter(Membership.org_id == org.id, Membership.user_id == user_id).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="user is not a member of this org")
    if not db.get(TeamMembership, (team_id, user_id)):
        db.add(TeamMembership(team_id=team_id, user_id=user_id))
        db.commit()


@router.delete("/orgs/current/teams/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_team_member(team_id: uuid.UUID, user_id: uuid.UUID,
                        ctx: tuple[Org, Membership] = Depends(require_role("owner", "admin")),
                        db: Session = Depends(get_db)) -> None:
    row = db.get(TeamMembership, (team_id, user_id))
    if row:
        db.delete(row)
        db.commit()
