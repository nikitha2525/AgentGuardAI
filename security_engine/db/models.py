"""
SQLAlchemy Database Models for AgentGuard AI.
Stores agents, tools, permission policies, security audit events, and detected threats.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Text, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class AgentModel(Base):
    __tablename__ = "agents"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    role = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    permissions = relationship("PermissionModel", back_populates="agent", cascade="all, delete-orphan")
    events = relationship("SecurityEventModel", back_populates="agent")


class ToolModel(Base):
    __tablename__ = "tools"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    actions = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class PermissionModel(Base):
    __tablename__ = "permissions"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String(64), ForeignKey("agents.id"), nullable=False)
    tool_name = Column(String(64), nullable=False)
    action_name = Column(String(64), nullable=False)
    decision = Column(String(16), default="ALLOW")  # ALLOW, REVIEW, BLOCK

    agent = relationship("AgentModel", back_populates="permissions")


class SecurityEventModel(Base):
    __tablename__ = "security_events"

    request_id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String(64), ForeignKey("agents.id"), nullable=False)
    user_input = Column(Text, nullable=True)
    tool = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    parameters = Column(JSON, default=dict)
    sanitized_parameters = Column(JSON, default=dict)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(16), default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    decision = Column(String(16), default="ALLOW")  # ALLOW, REVIEW, BLOCK
    threats = Column(JSON, default=list)
    reasons = Column(JSON, default=list)
    risk_breakdown = Column(JSON, default=dict)
    execution_time_ms = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    agent = relationship("AgentModel", back_populates="events")
    threat_records = relationship("ThreatModel", back_populates="event", cascade="all, delete-orphan")


class ThreatModel(Base):
    __tablename__ = "threats"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(64), ForeignKey("security_events.request_id"), nullable=False)
    category = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    rule_name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    matched_pattern = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    event = relationship("SecurityEventModel", back_populates="threat_records")


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor = Column(String(64), default="system")
    action = Column(String(64), nullable=False)
    details = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
