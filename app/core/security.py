"""
Core Security Module
Handles RS256 JWT signing/verifying and Argon2id password hashing
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import jwt, JWTError
from passlib.context import CryptContext
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os
import hashlib
import secrets

from app.infrastructure.security.key_loader import KeyLoader


# Argon2id password hashing context
# Using recommended parameters for 2026 security standards
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,  # 64 MB
    argon2__time_cost=3,       # 3 iterations
    argon2__parallelism=4,      # 4 parallel threads
    argon2__hash_len=32        # 32 bytes hash length
)


class SecurityService:
    """
    Security service for JWT and password operations
    Uses RS256 (asymmetric) for JWT signing
    Uses Argon2id for password hashing
    """
    
    def __init__(self, key_loader: KeyLoader):
        """
        Initialize security service with key loader
        
        Args:
            key_loader: KeyLoader instance for RSA key management
        """
        self.key_loader = key_loader
        self.algorithm = "RS256"
        self.access_token_expire_minutes = int(
            os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15")
        )
        self.refresh_token_expire_days = int(
            os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30")
        )
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using Argon2id
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password string
        """
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify password against hash
        
        Args:
            plain_password: Plain text password
            hashed_password: Hashed password from database
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception:
            # Handle legacy bcrypt hashes if migrating
            # For now, return False on any error
            return False
    
    def create_access_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token signed with RS256
        
        Args:
            data: Payload data to encode in token
            expires_delta: Optional custom expiration time
            
        Returns:
            Encoded JWT token string
        """
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=self.access_token_expire_minutes
            )
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        })
        
        private_key = self.key_loader.get_private_key()
        if not private_key:
            raise ValueError("Private key not available for token signing")
        
        encoded_jwt = jwt.encode(
            to_encode,
            private_key,
            algorithm=self.algorithm
        )
        
        return encoded_jwt
    
    def create_refresh_token(self, user_id: int) -> tuple[str, str]:
        """
        Create refresh token (random string) and its hash
        
        Args:
            user_id: User ID for the token
            
        Returns:
            Tuple of (token_string, token_hash)
        """
        # Generate cryptographically secure random token
        token_string = secrets.token_urlsafe(64)
        
        # Create SHA256 hash for database lookup
        token_hash = hashlib.sha256(token_string.encode()).hexdigest()
        
        return token_string, token_hash
    
    def verify_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT access token using RS256
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded payload if valid, None otherwise
        """
        try:
            public_key = self.key_loader.get_public_key()
            if not public_key:
                return None
            
            payload = jwt.decode(
                token,
                public_key,
                algorithms=[self.algorithm]
            )
            
            # Verify token type
            if payload.get("type") != "access":
                return None
            
            return payload
            
        except JWTError:
            return None
        except Exception:
            return None
    
    def get_refresh_token_expiry(self) -> datetime:
        """
        Get refresh token expiration datetime
        
        Returns:
            Datetime when refresh token expires
        """
        return datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
    
    def hash_refresh_token(self, token: str) -> str:
        """
        Hash refresh token for database storage
        
        Args:
            token: Plain refresh token string
            
        Returns:
            SHA256 hash of the token
        """
        return hashlib.sha256(token.encode()).hexdigest()
    
    def verify_refresh_token_hash(self, token: str, token_hash: str) -> bool:
        """
        Verify refresh token against stored hash
        
        Args:
            token: Plain refresh token string
            token_hash: Stored hash from database
            
        Returns:
            True if token matches hash, False otherwise
        """
        computed_hash = hashlib.sha256(token.encode()).hexdigest()
        return secrets.compare_digest(computed_hash, token_hash)
