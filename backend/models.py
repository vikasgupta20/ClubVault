"""
models.py - SQLAlchemy ORM Models
==================================
Defines all 7 database tables for the Zero-Trust Campus Club Vault:
  1. Users           – Authentication & role management
  2. Projects        – Club/team projects
  3. ProjectMembers  – Group-based access control
  4. AccessRequests  – Zero-trust access request pipeline
  5. Tokens          – Temporary JWT access tokens
  6. ActivityLogs    – Full audit trail
  7. CredentialsVault– Encrypted credential storage
"""

from sqlalchemy import (
    Column, Integer, String, Boolean, Float, DateTime, ForeignKey, Text
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(20), default="user")  # 'user' or 'host' (global default)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=True)
    is_frozen = Column(Boolean, default=False)  # Misuse detection freeze

    # Relationships
    hosted_projects = relationship("Project", back_populates="host")
    memberships = relationship("ProjectMember", back_populates="user")
    access_requests = relationship("AccessRequest", back_populates="requester")
    activity_logs = relationship("ActivityLog", back_populates="user")


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    project_name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    host_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    host = relationship("User", back_populates="hosted_projects")
    members = relationship("ProjectMember", back_populates="project")
    access_requests = relationship("AccessRequest", back_populates="project")
    credentials = relationship("CredentialsVault", back_populates="project")
    activity_logs = relationship("ActivityLog", back_populates="project")


class ProjectMember(Base):
    __tablename__ = "project_members"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role_in_project = Column(String(20), default="member")  # 'host' or 'member'
    joined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    project = relationship("Project", back_populates="members")
    user = relationship("User", back_populates="memberships")


class AccessRequest(Base):
    __tablename__ = "access_requests"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    requester_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    requested_permissions = Column(String(500), default="read")  # comma-separated
    requested_duration = Column(Integer, default=60)  # minutes (0–120)
    status = Column(String(20), default="pending")  # pending/approved/denied/terminated
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="Low")
    risk_reason = Column(Text, default="")
    ip_address = Column(String(45), default="")
    device_info = Column(String(300), default="")
    request_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_time = Column(DateTime, nullable=True)

    # Relationships
    requester = relationship("User", back_populates="access_requests")
    project = relationship("Project", back_populates="access_requests")
    token = relationship("Token", back_populates="access_request", uselist=False)


class Token(Base):
    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    request_id = Column(Integer, ForeignKey("access_requests.id"), unique=True, nullable=False)
    jwt_token = Column(Text, nullable=False)
    issued_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expiry_time = Column(DateTime, nullable=False)
    manually_terminated = Column(Boolean, default=False)

    # Relationships
    access_request = relationship("AccessRequest", back_populates="token")


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)
    action = Column(String(500), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    ip_address = Column(String(45), default="")

    # Relationships
    user = relationship("User", back_populates="activity_logs")
    project = relationship("Project", back_populates="activity_logs")


class CredentialsVault(Base):
    __tablename__ = "credentials_vault"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    credential_type = Column(String(50), nullable=False)  # firebase, github, mail, api_key
    credential_label = Column(String(200), default="")
    encrypted_value = Column(Text, nullable=False)  # Fernet-encrypted
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    project = relationship("Project", back_populates="credentials")
