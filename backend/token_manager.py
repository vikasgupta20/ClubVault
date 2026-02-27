"""
token_manager.py - Temporary Access Token System
==================================================
Implements Phase 4:
  - Time-bound JWT tokens for project access (0–2 hours)
  - Auto-expiry enforcement
  - Manual termination by host
  - Extension request workflow
  - Encrypted credential access gating
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt
from sqlalchemy.orm import Session
from cryptography.fernet import Fernet
import os

from models import Token, AccessRequest, CredentialsVault
from auth import SECRET_KEY, ALGORITHM

# ── Fernet Key for Credential Encryption ─────────────────
# In production, load from secure vault / env
FERNET_KEY = os.getenv("FERNET_KEY", Fernet.generate_key().decode())
_fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)


def create_project_access_token(
    user_id: int,
    project_id: int,
    permissions: str,
    duration_minutes: int,
) -> tuple[str, datetime]:
    """
    Create a scoped JWT for project access.
    Contains: user_id, project_id, permissions, expiry.
    Duration is capped at 120 minutes (2 hours).
    """
    duration_minutes = max(1, min(duration_minutes, 120))  # Clamp 1–120
    expiry = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)

    payload = {
        "sub": str(user_id),
        "project_id": project_id,
        "permissions": permissions,
        "token_type": "project_access",
        "exp": expiry,
        "iat": datetime.now(timezone.utc),
    }
    token_str = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token_str, expiry


def validate_project_token(token_str: str, db: Session) -> Optional[dict]:
    """
    Validate a project access token:
      1. Decode JWT (checks expiry)
      2. Check DB for manual termination
    Returns decoded payload or None if invalid.
    """
    try:
        payload = jwt.decode(token_str, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("token_type") != "project_access":
            return None

        # Check if token was manually terminated in DB
        db_token = db.query(Token).filter(Token.jwt_token == token_str).first()
        if db_token and db_token.manually_terminated:
            return None

        return payload
    except Exception:
        return None


def terminate_token(db: Session, request_id: int) -> bool:
    """Host terminates a token early."""
    db_token = db.query(Token).filter(Token.request_id == request_id).first()
    if db_token:
        db_token.manually_terminated = True
        # Also update access request status
        access_req = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
        if access_req:
            access_req.status = "terminated"
            access_req.resolved_time = datetime.now(timezone.utc)
        db.commit()
        return True
    return False


def is_token_active(db: Session, request_id: int) -> bool:
    """Check if a token is still active (not expired, not terminated)."""
    db_token = db.query(Token).filter(Token.request_id == request_id).first()
    if not db_token:
        return False
    if db_token.manually_terminated:
        return False
    if db_token.expiry_time.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return False
    return True


# ── Credential Encryption ────────────────────────────────
def encrypt_credential(plaintext: str) -> str:
    """Encrypt a credential value using Fernet symmetric encryption."""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_credential(encrypted: str) -> str:
    """Decrypt a credential value. Returns empty string on failure."""
    try:
        return _fernet.decrypt(encrypted.encode()).decode()
    except Exception:
        return ""


def get_project_credentials(db: Session, project_id: int, decrypt: bool = False) -> list[dict]:
    """
    Retrieve credentials for a project.
    Only decrypts if caller has active token (enforced at route level).
    """
    creds = db.query(CredentialsVault).filter(
        CredentialsVault.project_id == project_id
    ).all()
    result = []
    for c in creds:
        item = {
            "id": c.id,
            "credential_type": c.credential_type,
            "credential_label": c.credential_label,
        }
        if decrypt:
            item["value"] = decrypt_credential(c.encrypted_value)
        else:
            item["value"] = "••••••••"  # Masked
        result.append(item)
    return result
