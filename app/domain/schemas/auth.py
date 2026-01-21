"""
Domain Schemas for Authentication
Pydantic v2 Strict Models for Login/Register with rigid validation
"""
from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
import re


class LoginRequest(BaseModel):
    """Strict login request schema"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=6,
        max_length=255,
        description="User password (minimum 6 characters)"
    )

    @field_validator('password')
    @classmethod
    def validate_password_not_empty(cls, v: str) -> str:
        """Ensure password is not just whitespace"""
        if not v.strip():
            raise ValueError("Password cannot be empty or whitespace only")
        return v

    class Config:
        """Pydantic v2 config"""
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "securepassword123"
            }
        }


class RegisterRequest(BaseModel):
    """Strict registration request schema"""
    username: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Unique username"
    )
    email: EmailStr = Field(..., description="Unique email address")
    password: str = Field(
        ...,
        min_length=8,
        max_length=255,
        description="Password (minimum 8 characters, must be confirmed)"
    )
    password_confirmation: str = Field(
        ...,
        alias="password_confirmation",
        description="Password confirmation (must match password)"
    )
    account_type: Literal["personal", "private"] = Field(
        default="personal",
        description="Account type: personal or private"
    )
    
    # Optional profile fields
    first_name: Optional[str] = Field(None, max_length=255)
    last_name: Optional[str] = Field(None, max_length=255)
    public_name: Optional[str] = Field(None, max_length=100)
    birth_date: Optional[datetime] = None
    gender: Optional[Literal["M", "F", "O"]] = None
    city: Optional[str] = Field(None, max_length=255)
    location: Optional[str] = Field(None, max_length=100)
    country: Optional[str] = Field(None, max_length=255)
    phone: Optional[str] = Field(None, max_length=255)
    phone_prefix: Optional[str] = Field(None, max_length=10)

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format"""
        if not v.strip():
            raise ValueError("Username cannot be empty or whitespace only")
        # Allow alphanumeric, underscore, hyphen, dot
        if not re.match(r'^[a-zA-Z0-9_.-]+$', v):
            raise ValueError(
                "Username can only contain letters, numbers, underscores, hyphens, and dots"
            )
        return v.strip()

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Basic password strength validation"""
        if not v.strip():
            raise ValueError("Password cannot be empty or whitespace only")
        # Check for at least one letter and one number
        if not re.search(r'[a-zA-Z]', v):
            raise ValueError("Password must contain at least one letter")
        if not re.search(r'[0-9]', v):
            raise ValueError("Password must contain at least one number")
        return v

    @model_validator(mode='after')
    def validate_password_match(self) -> 'RegisterRequest':
        """Ensure password and confirmation match"""
        if self.password != self.password_confirmation:
            raise ValueError("Password and password confirmation do not match")
        return self

    class Config:
        """Pydantic v2 config"""
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "username": "johndoe",
                "email": "john@example.com",
                "password": "SecurePass123",
                "password_confirmation": "SecurePass123",
                "account_type": "personal",
                "first_name": "John",
                "last_name": "Doe"
            }
        }


class TokenResponse(BaseModel):
    """JWT token response schema"""
    access_token: str = Field(..., description="JWT access token (short-lived)")
    token_type: Literal["bearer"] = Field(default="bearer")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    refresh_token: str = Field(..., description="Refresh token (long-lived, revocable)")


class UserResponse(BaseModel):
    """User data response schema"""
    id: int
    email: str
    username: str
    account_type: str
    role: str
    verified: bool
    is_active: bool
    email_verified_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    on_vacation: bool = False
    powerseller: bool = False

    class Config:
        from_attributes = True


class AuthResponse(BaseModel):
    """Complete authentication response"""
    success: bool = True
    data: TokenResponse
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema"""
    refresh_token: str = Field(..., description="Valid refresh token")


class LogoutResponse(BaseModel):
    """Logout response schema"""
    success: bool = True
    message: str = "Logout effettuato con successo"
