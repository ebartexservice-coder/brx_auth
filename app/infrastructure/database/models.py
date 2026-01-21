"""
SQLAlchemy 2.0 Async Models
Maps legacy database tables exactly as they exist in legacy_dump.sql
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    BigInteger,
    Boolean,
    String,
    DateTime,
    Text,
    ForeignKey,
    Index,
    CheckConstraint,
    Enum as SQLEnum
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func
import enum


class Base(DeclarativeBase):
    """Base class for all models"""
    pass


class AccountType(str, enum.Enum):
    """Account type enumeration"""
    PERSONAL = "personal"
    PRIVATE = "private"


class UserRole(str, enum.Enum):
    """User role enumeration"""
    USER = "user"
    ADMIN = "admin"


class User(Base):
    """
    Users table - EXACT mapping from legacy_dump.sql
    DO NOT change column names - they must match the legacy database exactly
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(BigInteger(), "mysql"),
        primary_key=True,
        autoincrement=True
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Webhook fields
    webhook_token: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, unique=True, index=True)
    webhook_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    webhook_enabled: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=True)
    webhook_last_received: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Authentication fields
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    remember_token: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Timestamps
    created_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=True
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=True
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Account metadata
    account_type: Mapped[str] = mapped_column(String(255), nullable=False, default="personal")
    role: Mapped[str] = mapped_column(String(255), nullable=False, default="user")
    verified: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean(),
        default=True,
        nullable=False,
        comment="Stato attivo dell'utente"
    )
    on_vacation: Mapped[bool] = mapped_column(
        Boolean(),
        default=False,
        nullable=False,
        comment="Utente in vacanza"
    )
    powerseller: Mapped[bool] = mapped_column(
        Boolean(),
        default=False,
        nullable=False,
        comment="Flag per powerseller"
    )

    # Relationships
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, username={self.username})>"


class RefreshToken(Base):
    """
    Refresh Tokens table - NEW table for dual token system
    Links to existing users.id via foreign key
    """
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(BigInteger(), "mysql"),
        primary_key=True,
        autoincrement=True
    )
    user_id: Mapped[int] = mapped_column(
        BigInteger().with_variant(BigInteger(), "mysql"),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    token: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Hashed refresh token"
    )
    token_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="SHA256 hash of the token for lookup"
    )
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    
    # Token lifecycle
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")

    # Indexes for performance
    __table_args__ = (
        Index("idx_refresh_tokens_user_expires", "user_id", "expires_at"),
        Index("idx_refresh_tokens_token_hash", "token_hash"),
        Index("idx_refresh_tokens_revoked", "revoked_at"),
    )

    def is_expired(self) -> bool:
        """Check if token is expired"""
        from datetime import timezone
        return datetime.now(timezone.utc) >= self.expires_at

    def is_revoked(self) -> bool:
        """Check if token is revoked"""
        return self.revoked_at is not None

    def is_valid(self) -> bool:
        """Check if token is valid (not expired and not revoked)"""
        return not self.is_expired() and not self.is_revoked()

    def __repr__(self) -> str:
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})>"


class LoginAuditLog(Base):
    """
    Login Audit Logs table - NEW table for security auditing
    Tracks all login attempts (successful and failed)
    """
    __tablename__ = "login_audit_logs"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(BigInteger(), "mysql"),
        primary_key=True,
        autoincrement=True
    )
    user_id: Mapped[Optional[int]] = mapped_column(
        BigInteger().with_variant(BigInteger(), "mysql"),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    
    # Login attempt details
    success: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False, index=True)
    failure_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Device and location info (stored as JSON)
    device_info: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    location_info: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    # Indexes for performance
    __table_args__ = (
        Index("idx_login_audit_user_created", "user_id", "created_at"),
        Index("idx_login_audit_ip_created", "ip_address", "created_at"),
        Index("idx_login_audit_email_created", "email", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<LoginAuditLog(id={self.id}, user_id={self.user_id}, success={self.success})>"


class RateLimitEvent(Base):
    """
    Rate Limit Events table - NEW table for tracking rate limiting
    Used for brute force protection and global rate limiting
    """
    __tablename__ = "rate_limit_events"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(BigInteger(), "mysql"),
        primary_key=True,
        autoincrement=True
    )
    identifier: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="IP address, email, or user_id"
    )
    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="login_attempt, api_request, etc."
    )
    count: Mapped[int] = mapped_column(BigInteger(), default=1, nullable=False)
    
    # Window tracking
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    # Indexes for performance
    __table_args__ = (
        Index("idx_rate_limit_identifier_type", "identifier", "event_type"),
        Index("idx_rate_limit_window", "window_start", "window_end"),
    )

    def __repr__(self) -> str:
        return f"<RateLimitEvent(id={self.id}, identifier={self.identifier}, count={self.count})>"
