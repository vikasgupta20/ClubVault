"""
main.py - Zero-Trust Campus Club Vault API Server
====================================================
Central FastAPI application integrating all phases:
  Phase 1: Core REST API architecture
  Phase 2: Database-backed user/project/token models
  Phase 3: AI risk engine integration
  Phase 4: Consent, timer, token system
  Phase 5: Group & vault system
  Phase 6: Host dashboard features
  Phase 7: Misuse detection
  Phase 8: Chatbot endpoint
  Phase 10: Security practices (CORS, validation, encryption)
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr, Field, validator
from sqlalchemy.orm import Session

from database import get_db, init_db
from models import (
    User, Project, ProjectMember, AccessRequest,
    Token, ActivityLog, CredentialsVault,
)
from auth import (
    hash_password, verify_password, create_access_token,
    get_current_user, get_client_ip, decode_token,
)
from token_manager import (
    create_project_access_token, terminate_token, is_token_active,
    encrypt_credential, decrypt_credential, get_project_credentials,
)
from risk_engine import (
    analyze_risk_with_gemini, build_risk_context, check_misuse,
)
from chatbot import get_chatbot_response

import os

# ══════════════════════════════════════════════════════════
# App Initialization
# ══════════════════════════════════════════════════════════
app = FastAPI(
    title="Zero-Trust Campus Club Vault",
    description="AI-powered zero-trust access control for campus club collaboration",
    version="1.0.0",
)

# Phase 10: CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.on_event("startup")
def startup():
    init_db()


# ══════════════════════════════════════════════════════════
# Pydantic Schemas (Input Validation - Phase 10)
# ══════════════════════════════════════════════════════════

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=80)
    email: str = Field(..., max_length=120)
    password: str = Field(..., min_length=6, max_length=128)
    role: str = Field(default="user")

    @validator("role")
    def validate_role(cls, v):
        if v not in ("user", "host"):
            raise ValueError("Role must be 'user' or 'host'")
        return v

    @validator("username")
    def validate_username(cls, v):
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username must be alphanumeric (underscores and hyphens allowed)")
        return v


class UserLogin(BaseModel):
    username: str
    password: str


class ProjectCreate(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)


class AccessRequestCreate(BaseModel):
    project_id: int
    requested_permissions: str = Field(default="read", max_length=500)
    requested_duration: int = Field(default=60, ge=1, le=120)
    device_info: str = Field(default="Web Browser", max_length=300)


class AccessDecision(BaseModel):
    request_id: int
    action: str  # approve, deny, terminate

    @validator("action")
    def validate_action(cls, v):
        if v not in ("approve", "deny", "terminate"):
            raise ValueError("Action must be 'approve', 'deny', or 'terminate'")
        return v


class CredentialAdd(BaseModel):
    project_id: int
    credential_type: str = Field(..., max_length=50)
    credential_label: str = Field(default="", max_length=200)
    value: str = Field(..., min_length=1)


class ExtensionRequest(BaseModel):
    request_id: int
    additional_minutes: int = Field(default=30, ge=1, le=120)


class ChatMessage(BaseModel):
    message: str = Field(..., min_length=1, max_length=500)


class PermissionUpdate(BaseModel):
    request_id: int
    new_permissions: str = Field(..., max_length=500)


# ── Helper: Log Activity ─────────────────────────────────
def log_activity(db: Session, user_id: int, action: str, ip: str, project_id: int = None):
    log = ActivityLog(
        user_id=user_id,
        project_id=project_id,
        action=action,
        ip_address=ip,
    )
    db.add(log)
    db.commit()


# ══════════════════════════════════════════════════════════
# Frontend Routes
# ══════════════════════════════════════════════════════════

@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/dashboard")
async def serve_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"))


@app.get("/host")
async def serve_host():
    return FileResponse(os.path.join(FRONTEND_DIR, "host.html"))


# ══════════════════════════════════════════════════════════
# AUTH ENDPOINTS (Phase 1 & 10)
# ══════════════════════════════════════════════════════════

@app.post("/api/auth/register")
async def register(data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user with bcrypt-hashed password."""
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "Username already taken")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email already registered")

    user = User(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role=data.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": str(user.id), "role": user.role})
    return {
        "message": "Registration successful",
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    }


@app.post("/api/auth/login")
async def login(data: UserLogin, request: Request, db: Session = Depends(get_db)):
    """Authenticate user and issue a JWT session token."""
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    if not user.is_active:
        raise HTTPException(403, "Account deactivated")

    token = create_access_token({"sub": str(user.id), "role": user.role})
    log_activity(db, user.id, "login", get_client_ip(request))

    return {
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "is_frozen": user.is_frozen,
        },
    }


@app.get("/api/auth/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user profile."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "is_frozen": current_user.is_frozen,
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
    }


# ══════════════════════════════════════════════════════════
# PROJECT ENDPOINTS (Phase 5)
# ══════════════════════════════════════════════════════════

@app.post("/api/projects")
async def create_project(
    data: ProjectCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new project. Creator becomes host."""
    project = Project(
        project_name=data.project_name,
        description=data.description,
        host_id=current_user.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    # Add creator as host member
    member = ProjectMember(
        project_id=project.id,
        user_id=current_user.id,
        role_in_project="host",
    )
    db.add(member)
    db.commit()

    log_activity(db, current_user.id, f"Created project: {data.project_name}", get_client_ip(request), project.id)

    return {
        "message": "Project created",
        "project": {
            "id": project.id,
            "project_name": project.project_name,
            "description": project.description,
            "host_id": project.host_id,
        },
    }


@app.get("/api/projects")
async def list_projects(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all projects (browsable for access requests)."""
    projects = db.query(Project).all()
    result = []
    for p in projects:
        host = db.query(User).filter(User.id == p.host_id).first()
        member_count = db.query(ProjectMember).filter(ProjectMember.project_id == p.id).count()
        result.append({
            "id": p.id,
            "project_name": p.project_name,
            "description": p.description,
            "host_id": p.host_id,
            "host_username": host.username if host else "Unknown",
            "member_count": member_count,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        })
    return {"projects": result}


@app.get("/api/projects/{project_id}")
async def get_project(
    project_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get project details."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    members = db.query(ProjectMember).filter(ProjectMember.project_id == project_id).all()
    member_list = []
    for m in members:
        u = db.query(User).filter(User.id == m.user_id).first()
        member_list.append({
            "user_id": m.user_id,
            "username": u.username if u else "Unknown",
            "role_in_project": m.role_in_project,
        })

    return {
        "id": project.id,
        "project_name": project.project_name,
        "description": project.description,
        "host_id": project.host_id,
        "members": member_list,
    }


@app.get("/api/my-projects")
async def my_projects(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get projects hosted by current user."""
    projects = db.query(Project).filter(Project.host_id == current_user.id).all()
    return {
        "projects": [
            {
                "id": p.id,
                "project_name": p.project_name,
                "description": p.description,
                "created_at": p.created_at.isoformat() if p.created_at else None,
            }
            for p in projects
        ]
    }


# ══════════════════════════════════════════════════════════
# ACCESS REQUEST ENDPOINTS (Phase 3, 4, 7)
# ══════════════════════════════════════════════════════════

@app.post("/api/access-requests")
async def create_access_request(
    data: AccessRequestCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Submit an access request. Triggers AI risk analysis.
    Misuse detection may freeze the account.
    """
    # Check project exists
    project = db.query(Project).filter(Project.id == data.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    # Can't request access to own project
    if project.host_id == current_user.id:
        raise HTTPException(400, "You are the host of this project")

    # Check for existing pending request
    existing = db.query(AccessRequest).filter(
        AccessRequest.requester_id == current_user.id,
        AccessRequest.project_id == data.project_id,
        AccessRequest.status == "pending",
    ).first()
    if existing:
        raise HTTPException(400, "You already have a pending request for this project")

    ip = get_client_ip(request)

    # Phase 7: Misuse detection
    if check_misuse(db, current_user.id):
        current_user.is_frozen = True
        db.commit()
        log_activity(db, current_user.id, "MISUSE DETECTED - Account frozen", ip, data.project_id)
        raise HTTPException(
            403,
            "Suspicious activity detected. Your account has been temporarily frozen. Contact the host for re-approval.",
        )

    # Phase 3: AI Risk Analysis
    risk_context = await build_risk_context(
        db, current_user, data.project_id,
        data.requested_permissions, data.requested_duration,
        ip, data.device_info,
    )
    risk_result = await analyze_risk_with_gemini(risk_context)

    # Create access request
    access_req = AccessRequest(
        requester_id=current_user.id,
        project_id=data.project_id,
        requested_permissions=data.requested_permissions,
        requested_duration=data.requested_duration,
        risk_score=risk_result["risk_score"],
        risk_level=risk_result["risk_level"],
        risk_reason=risk_result["explanation"],
        ip_address=ip,
        device_info=data.device_info,
    )
    db.add(access_req)
    db.commit()
    db.refresh(access_req)

    log_activity(db, current_user.id, f"Access request submitted (risk: {risk_result['risk_level']})", ip, data.project_id)

    return {
        "message": "Access request submitted",
        "request": {
            "id": access_req.id,
            "status": access_req.status,
            "risk_score": access_req.risk_score,
            "risk_level": access_req.risk_level,
            "risk_reason": access_req.risk_reason,
        },
    }


@app.get("/api/access-requests/pending")
async def get_pending_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get pending access requests for projects hosted by current user (Phase 6)."""
    hosted_projects = db.query(Project).filter(Project.host_id == current_user.id).all()
    project_ids = [p.id for p in hosted_projects]

    if not project_ids:
        return {"requests": []}

    requests = db.query(AccessRequest).filter(
        AccessRequest.project_id.in_(project_ids),
        AccessRequest.status == "pending",
    ).order_by(AccessRequest.request_time.desc()).all()

    result = []
    for r in requests:
        requester = db.query(User).filter(User.id == r.requester_id).first()
        project = db.query(Project).filter(Project.id == r.project_id).first()
        result.append({
            "id": r.id,
            "requester_id": r.requester_id,
            "requester_username": requester.username if requester else "Unknown",
            "project_id": r.project_id,
            "project_name": project.project_name if project else "Unknown",
            "requested_permissions": r.requested_permissions,
            "requested_duration": r.requested_duration,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "risk_reason": r.risk_reason,
            "ip_address": r.ip_address,
            "device_info": r.device_info,
            "request_time": r.request_time.isoformat() if r.request_time else None,
        })

    return {"requests": result}


@app.get("/api/access-requests/all")
async def get_all_requests_for_host(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get ALL access requests for projects hosted by current user (Phase 6)."""
    hosted_projects = db.query(Project).filter(Project.host_id == current_user.id).all()
    project_ids = [p.id for p in hosted_projects]

    if not project_ids:
        return {"requests": []}

    requests = db.query(AccessRequest).filter(
        AccessRequest.project_id.in_(project_ids),
    ).order_by(AccessRequest.request_time.desc()).all()

    result = []
    for r in requests:
        requester = db.query(User).filter(User.id == r.requester_id).first()
        project = db.query(Project).filter(Project.id == r.project_id).first()
        token_active = is_token_active(db, r.id) if r.status == "approved" else False
        result.append({
            "id": r.id,
            "requester_id": r.requester_id,
            "requester_username": requester.username if requester else "Unknown",
            "project_id": r.project_id,
            "project_name": project.project_name if project else "Unknown",
            "requested_permissions": r.requested_permissions,
            "requested_duration": r.requested_duration,
            "status": r.status,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "risk_reason": r.risk_reason,
            "ip_address": r.ip_address,
            "request_time": r.request_time.isoformat() if r.request_time else None,
            "token_active": token_active,
        })

    return {"requests": result}


@app.get("/api/access-requests/my")
async def get_my_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get current user's access requests."""
    requests = db.query(AccessRequest).filter(
        AccessRequest.requester_id == current_user.id,
    ).order_by(AccessRequest.request_time.desc()).all()

    result = []
    for r in requests:
        project = db.query(Project).filter(Project.id == r.project_id).first()
        token_active = is_token_active(db, r.id) if r.status == "approved" else False
        token_data = db.query(Token).filter(Token.request_id == r.id).first()
        result.append({
            "id": r.id,
            "project_id": r.project_id,
            "project_name": project.project_name if project else "Unknown",
            "requested_permissions": r.requested_permissions,
            "requested_duration": r.requested_duration,
            "status": r.status,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "risk_reason": r.risk_reason,
            "request_time": r.request_time.isoformat() if r.request_time else None,
            "token_active": token_active,
            "expiry_time": token_data.expiry_time.isoformat() if token_data and token_data.expiry_time else None,
        })

    return {"requests": result}


# ══════════════════════════════════════════════════════════
# HOST DECISION ENDPOINTS (Phase 4, 6)
# ══════════════════════════════════════════════════════════

@app.post("/api/access-requests/decide")
async def decide_access_request(
    data: AccessDecision,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Host approves, denies, or terminates an access request."""
    access_req = db.query(AccessRequest).filter(AccessRequest.id == data.request_id).first()
    if not access_req:
        raise HTTPException(404, "Access request not found")

    # Verify host ownership
    project = db.query(Project).filter(Project.id == access_req.project_id).first()
    if not project or project.host_id != current_user.id:
        raise HTTPException(403, "You are not the host of this project")

    ip = get_client_ip(request)

    if data.action == "approve":
        if access_req.status != "pending":
            raise HTTPException(400, "Request is not pending")

        access_req.status = "approved"
        access_req.resolved_time = datetime.now(timezone.utc)

        # Create project access token
        token_str, expiry = create_project_access_token(
            access_req.requester_id,
            access_req.project_id,
            access_req.requested_permissions,
            access_req.requested_duration,
        )

        db_token = Token(
            request_id=access_req.id,
            jwt_token=token_str,
            expiry_time=expiry,
        )
        db.add(db_token)

        # Add user to project group (Phase 5)
        existing_member = db.query(ProjectMember).filter(
            ProjectMember.project_id == access_req.project_id,
            ProjectMember.user_id == access_req.requester_id,
        ).first()
        if not existing_member:
            member = ProjectMember(
                project_id=access_req.project_id,
                user_id=access_req.requester_id,
                role_in_project="member",
            )
            db.add(member)

        db.commit()
        log_activity(db, current_user.id, f"Approved access request #{access_req.id}", ip, access_req.project_id)

        return {
            "message": "Access approved",
            "token_expiry": expiry.isoformat(),
        }

    elif data.action == "deny":
        if access_req.status != "pending":
            raise HTTPException(400, "Request is not pending")

        access_req.status = "denied"
        access_req.resolved_time = datetime.now(timezone.utc)
        db.commit()
        log_activity(db, current_user.id, f"Denied access request #{access_req.id}", ip, access_req.project_id)

        return {"message": "Access denied"}

    elif data.action == "terminate":
        if access_req.status != "approved":
            raise HTTPException(400, "Request is not active")

        terminate_token(db, access_req.id)
        log_activity(db, current_user.id, f"Terminated access for request #{access_req.id}", ip, access_req.project_id)

        return {"message": "Access terminated"}


@app.post("/api/access-requests/extend")
async def extend_access(
    data: ExtensionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Host extends an active token's duration."""
    access_req = db.query(AccessRequest).filter(AccessRequest.id == data.request_id).first()
    if not access_req:
        raise HTTPException(404, "Access request not found")

    project = db.query(Project).filter(Project.id == access_req.project_id).first()
    if not project or project.host_id != current_user.id:
        raise HTTPException(403, "You are not the host of this project")

    db_token = db.query(Token).filter(Token.request_id == data.request_id).first()
    if not db_token:
        raise HTTPException(404, "Token not found")

    # Extend the token expiry
    new_expiry = db_token.expiry_time.replace(tzinfo=timezone.utc) + timedelta(minutes=data.additional_minutes)
    # Regenerate token with new expiry
    new_token_str, _ = create_project_access_token(
        access_req.requester_id,
        access_req.project_id,
        access_req.requested_permissions,
        int((new_expiry - datetime.now(timezone.utc)).total_seconds() / 60),
    )
    db_token.jwt_token = new_token_str
    db_token.expiry_time = new_expiry
    db_token.manually_terminated = False

    # Update the access request status back to approved if it was terminated
    access_req.status = "approved"
    db.commit()

    ip = get_client_ip(request)
    log_activity(db, current_user.id, f"Extended access for request #{data.request_id} by {data.additional_minutes}min", ip, access_req.project_id)

    return {
        "message": f"Access extended by {data.additional_minutes} minutes",
        "new_expiry": new_expiry.isoformat(),
    }


@app.post("/api/access-requests/update-permissions")
async def update_permissions(
    data: PermissionUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Host modifies user permissions on an active request."""
    access_req = db.query(AccessRequest).filter(AccessRequest.id == data.request_id).first()
    if not access_req:
        raise HTTPException(404, "Access request not found")

    project = db.query(Project).filter(Project.id == access_req.project_id).first()
    if not project or project.host_id != current_user.id:
        raise HTTPException(403, "You are not the host of this project")

    access_req.requested_permissions = data.new_permissions
    db.commit()

    ip = get_client_ip(request)
    log_activity(db, current_user.id, f"Updated permissions for request #{data.request_id} to {data.new_permissions}", ip, access_req.project_id)

    return {"message": "Permissions updated", "new_permissions": data.new_permissions}


# ══════════════════════════════════════════════════════════
# REQUEST EXTENSION BY USER (Phase 4)
# ══════════════════════════════════════════════════════════

@app.post("/api/access-requests/request-extension")
async def request_extension(
    data: ExtensionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """User requests an extension (creates a new pending request referencing the original)."""
    original = db.query(AccessRequest).filter(AccessRequest.id == data.request_id).first()
    if not original:
        raise HTTPException(404, "Original request not found")
    if original.requester_id != current_user.id:
        raise HTTPException(403, "Not your request")

    ip = get_client_ip(request)

    # Create a new access request as an extension
    ext_req = AccessRequest(
        requester_id=current_user.id,
        project_id=original.project_id,
        requested_permissions=original.requested_permissions,
        requested_duration=data.additional_minutes,
        status="pending",
        risk_score=original.risk_score,
        risk_level=original.risk_level,
        risk_reason=f"Extension request for #{original.id}",
        ip_address=ip,
        device_info=original.device_info,
    )
    db.add(ext_req)
    db.commit()

    log_activity(db, current_user.id, f"Requested extension for request #{original.id}", ip, original.project_id)

    return {"message": "Extension request submitted", "new_request_id": ext_req.id}


# ══════════════════════════════════════════════════════════ 
# CREDENTIALS VAULT ENDPOINTS (Phase 5)
# ══════════════════════════════════════════════════════════

@app.post("/api/credentials")
async def add_credential(
    data: CredentialAdd,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Host adds encrypted credentials to project vault."""
    project = db.query(Project).filter(Project.id == data.project_id).first()
    if not project or project.host_id != current_user.id:
        raise HTTPException(403, "Only the host can add credentials")

    cred = CredentialsVault(
        project_id=data.project_id,
        credential_type=data.credential_type,
        credential_label=data.credential_label,
        encrypted_value=encrypt_credential(data.value),
    )
    db.add(cred)
    db.commit()

    ip = get_client_ip(request)
    log_activity(db, current_user.id, f"Added {data.credential_type} credential", ip, data.project_id)

    return {"message": "Credential added securely"}


@app.get("/api/credentials/{project_id}")
async def view_credentials(
    project_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    View project credentials.
    Host always sees decrypted. Members see decrypted ONLY with active token.
    """
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    ip = get_client_ip(request)

    # Host can always see
    if project.host_id == current_user.id:
        creds = get_project_credentials(db, project_id, decrypt=True)
        log_activity(db, current_user.id, "Viewed credentials (host)", ip, project_id)
        return {"credentials": creds, "access_type": "host"}

    # Member needs active token
    active_request = db.query(AccessRequest).filter(
        AccessRequest.requester_id == current_user.id,
        AccessRequest.project_id == project_id,
        AccessRequest.status == "approved",
    ).first()

    if not active_request or not is_token_active(db, active_request.id):
        creds = get_project_credentials(db, project_id, decrypt=False)
        return {"credentials": creds, "access_type": "restricted", "message": "Active token required to view credentials"}

    creds = get_project_credentials(db, project_id, decrypt=True)
    log_activity(db, current_user.id, "Viewed credentials (member)", ip, project_id)
    return {"credentials": creds, "access_type": "member"}


@app.delete("/api/credentials/{credential_id}")
async def delete_credential(
    credential_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Host deletes a credential from the vault."""
    cred = db.query(CredentialsVault).filter(CredentialsVault.id == credential_id).first()
    if not cred:
        raise HTTPException(404, "Credential not found")

    project = db.query(Project).filter(Project.id == cred.project_id).first()
    if not project or project.host_id != current_user.id:
        raise HTTPException(403, "Only the host can delete credentials")

    db.delete(cred)
    db.commit()
    return {"message": "Credential deleted"}


# ══════════════════════════════════════════════════════════
# ACTIVITY LOGS ENDPOINT (Phase 6)
# ══════════════════════════════════════════════════════════

@app.get("/api/activity-logs/{project_id}")
async def get_activity_logs(
    project_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get activity logs for a project (host only)."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project or project.host_id != current_user.id:
        raise HTTPException(403, "Only the host can view activity logs")

    logs = db.query(ActivityLog).filter(
        ActivityLog.project_id == project_id,
    ).order_by(ActivityLog.timestamp.desc()).limit(100).all()

    result = []
    for log in logs:
        user = db.query(User).filter(User.id == log.user_id).first()
        result.append({
            "id": log.id,
            "user_id": log.user_id,
            "username": user.username if user else "Unknown",
            "action": log.action,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "ip_address": log.ip_address,
        })

    return {"logs": result}


@app.get("/api/activity-logs")
async def get_all_activity_logs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get all activity logs across all hosted projects."""
    hosted_projects = db.query(Project).filter(Project.host_id == current_user.id).all()
    project_ids = [p.id for p in hosted_projects]

    logs = db.query(ActivityLog).filter(
        ActivityLog.project_id.in_(project_ids) if project_ids else True,
    ).order_by(ActivityLog.timestamp.desc()).limit(200).all()

    result = []
    for log in logs:
        user = db.query(User).filter(User.id == log.user_id).first()
        project = db.query(Project).filter(Project.id == log.project_id).first() if log.project_id else None
        result.append({
            "id": log.id,
            "username": user.username if user else "Unknown",
            "project_name": project.project_name if project else "N/A",
            "action": log.action,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "ip_address": log.ip_address,
        })

    return {"logs": result}


# ══════════════════════════════════════════════════════════
# MISUSE / UNFREEZE ENDPOINTS (Phase 7)
# ══════════════════════════════════════════════════════════

@app.post("/api/users/unfreeze/{user_id}")
async def unfreeze_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Host unfreezes a user's account (re-approval)."""
    # Check that current user is a host of at least one project the frozen user requested access to
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(404, "User not found")

    # Verify the current user is a host that has authority
    hosted_projects = db.query(Project).filter(Project.host_id == current_user.id).all()
    if not hosted_projects:
        raise HTTPException(403, "You are not a host of any projects")

    target_user.is_frozen = False
    db.commit()

    ip = get_client_ip(request)
    log_activity(db, current_user.id, f"Unfroze user {target_user.username}", ip)

    return {"message": f"User {target_user.username} has been unfrozen"}


# ══════════════════════════════════════════════════════════
# CHATBOT ENDPOINT (Phase 8)
# ══════════════════════════════════════════════════════════

@app.post("/api/chatbot")
async def chatbot_endpoint(data: ChatMessage):
    """Chatbot for platform navigation help."""
    response = await get_chatbot_response(data.message)
    return {"response": response}


# ══════════════════════════════════════════════════════════
# STATS ENDPOINT (Dashboard)
# ══════════════════════════════════════════════════════════

@app.get("/api/stats")
async def get_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get dashboard statistics."""
    hosted_projects = db.query(Project).filter(Project.host_id == current_user.id).count()
    member_projects = db.query(ProjectMember).filter(
        ProjectMember.user_id == current_user.id,
        ProjectMember.role_in_project == "member",
    ).count()
    pending_requests = 0
    active_sessions = 0

    if hosted_projects > 0:
        project_ids = [p.id for p in db.query(Project).filter(Project.host_id == current_user.id).all()]
        pending_requests = db.query(AccessRequest).filter(
            AccessRequest.project_id.in_(project_ids),
            AccessRequest.status == "pending",
        ).count()
        approved = db.query(AccessRequest).filter(
            AccessRequest.project_id.in_(project_ids),
            AccessRequest.status == "approved",
        ).all()
        active_sessions = sum(1 for a in approved if is_token_active(db, a.id))

    my_active = db.query(AccessRequest).filter(
        AccessRequest.requester_id == current_user.id,
        AccessRequest.status == "approved",
    ).all()
    my_active_count = sum(1 for a in my_active if is_token_active(db, a.id))

    return {
        "hosted_projects": hosted_projects,
        "member_projects": member_projects,
        "pending_requests": pending_requests,
        "active_sessions": active_sessions,
        "my_active_tokens": my_active_count,
    }


# ══════════════════════════════════════════════════════════
# Run Server
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
