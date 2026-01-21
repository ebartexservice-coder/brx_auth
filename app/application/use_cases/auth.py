"""
Authentication Use Cases
Business logic for authentication operations
"""
from typing import Optional, Tuple
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    AuthResponse,
    TokenResponse,
    UserResponse
)
from app.infrastructure.database.models import User, RefreshToken
from app.infrastructure.repositories.user_repository import UserRepository
from app.infrastructure.repositories.refresh_token_repository import RefreshTokenRepository
from app.core.security import SecurityService
from app.infrastructure.cache.redis_service import RedisService


class AuthenticationError(Exception):
    """Base exception for authentication errors"""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Invalid email or password"""
    pass


class UserNotFoundError(AuthenticationError):
    """User not found"""
    pass


class UserInactiveError(AuthenticationError):
    """User account is inactive"""
    pass


class AccountLockedError(AuthenticationError):
    """Account is locked due to too many failed attempts"""
    pass


class EmailAlreadyExistsError(AuthenticationError):
    """Email already registered"""
    pass


class UsernameAlreadyExistsError(AuthenticationError):
    """Username already taken"""
    pass


class InvalidRefreshTokenError(AuthenticationError):
    """Invalid or expired refresh token"""
    pass


class LoginUseCase:
    """Use case for user login with password migration support"""
    
    def __init__(
        self,
        session: AsyncSession,
        security_service: SecurityService,
        redis_service: RedisService
    ):
        """
        Initialize login use case
        
        Args:
            session: Database session
            security_service: Security service instance
            redis_service: Redis service instance
        """
        self.session = session
        self.security_service = security_service
        self.redis_service = redis_service
        self.user_repo = UserRepository(session)
        self.refresh_token_repo = RefreshTokenRepository(session)
        
        # Brute force protection settings
        import os
        self.max_login_attempts = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
        self.lockout_window_minutes = int(os.getenv("ACCOUNT_LOCKOUT_MINUTES", "30"))
    
    async def execute(
        self,
        request: LoginRequest,
        ip_address: str,
        user_agent: Optional[str] = None
    ) -> AuthResponse:
        """
        Execute login use case
        
        Args:
            request: Login request with email and password
            ip_address: Client IP address
            user_agent: Optional user agent string
            
        Returns:
            AuthResponse with tokens and user data
            
        Raises:
            InvalidCredentialsError: If credentials are invalid
            UserInactiveError: If user account is inactive
            AccountLockedError: If account is locked
        """
        # Check rate limiting
        rate_limit_key = f"login:{ip_address}"
        is_allowed, count, limit = await self.redis_service.check_rate_limit(
            rate_limit_key,
            event_type="login_attempt",
            window_minutes=1
        )
        
        if not is_allowed:
            raise AuthenticationError(
                f"Too many login attempts. Please try again later."
            )
        
        # Get user by email
        user = await self.user_repo.get_by_email(request.email)
        
        if not user:
            # Don't reveal if user exists - same error message
            raise InvalidCredentialsError("Invalid email or password")
        
        # Check if account is locked
        lockout_key = f"account_lockout:{user.id}"
        lockout_count = await self.redis_service.get_counter(lockout_key)
        
        if lockout_count >= self.max_login_attempts:
            raise AccountLockedError(
                f"Account locked due to too many failed attempts. "
                f"Please try again in {self.lockout_window_minutes} minutes."
            )
        
        # Verify password (supports both Argon2id and legacy Bcrypt)
        is_valid = self.security_service.verify_password(
            request.password,
            user.password
        )
        
        if not is_valid:
            # Increment failed login counter
            failed_key = f"failed_logins:{user.id}"
            failed_count = await self.redis_service.increment_counter(
                failed_key,
                ttl_seconds=self.lockout_window_minutes * 60
            )
            
            # Lock account if threshold reached
            if failed_count >= self.max_login_attempts:
                await self.redis_service.set_cache(
                    lockout_key,
                    "locked",
                    ttl_seconds=self.lockout_window_minutes * 60
                )
            
            raise InvalidCredentialsError("Invalid email or password")
        
        # Password is valid - check if it's legacy Bcrypt and migrate
        if self.security_service.is_legacy_hash(user.password):
            # Re-hash with Argon2id
            new_hash = self.security_service.hash_password(request.password)
            await self.user_repo.update_password(user.id, new_hash)
            await self.session.commit()
        
        # Reset failed login counter on successful login
        await self.redis_service.reset_counter(f"failed_logins:{user.id}")
        await self.redis_service.reset_counter(lockout_key)
        
        # Check if user is active
        if not user.is_active:
            raise UserInactiveError("Account is not active")
        
        # Update last login
        await self.user_repo.update_last_login(user.id)
        
        # Generate tokens
        access_token = self.security_service.create_access_token(
            data={"sub": str(user.id), "email": user.email}
        )
        
        token_string, token_hash = self.security_service.create_refresh_token(user.id)
        expires_at = self.security_service.get_refresh_token_expiry()
        
        # Save refresh token
        refresh_token = await self.refresh_token_repo.create(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        await self.session.commit()
        
        # Build response
        token_response = TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=self.security_service.access_token_expire_minutes * 60,
            refresh_token=token_string
        )
        
        user_response = UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            account_type=user.account_type,
            role=user.role,
            verified=user.verified,
            is_active=user.is_active,
            email_verified_at=user.email_verified_at,
            last_login_at=user.last_login_at,
            on_vacation=user.on_vacation,
            powerseller=user.powerseller
        )
        
        return AuthResponse(
            success=True,
            data=token_response,
            user=user_response
        )


class RegisterUseCase:
    """Use case for user registration"""
    
    def __init__(
        self,
        session: AsyncSession,
        security_service: SecurityService
    ):
        """
        Initialize register use case
        
        Args:
            session: Database session
            security_service: Security service instance
        """
        self.session = session
        self.security_service = security_service
        self.user_repo = UserRepository(session)
        self.refresh_token_repo = RefreshTokenRepository(session)
    
    async def execute(
        self,
        request: RegisterRequest,
        ip_address: str,
        user_agent: Optional[str] = None
    ) -> AuthResponse:
        """
        Execute registration use case
        
        Args:
            request: Registration request
            ip_address: Client IP address
            user_agent: Optional user agent string
            
        Returns:
            AuthResponse with tokens and user data
            
        Raises:
            EmailAlreadyExistsError: If email already registered
            UsernameAlreadyExistsError: If username already taken
        """
        # Check if email exists
        if await self.user_repo.exists_by_email(request.email):
            raise EmailAlreadyExistsError("Email already registered")
        
        # Check if username exists
        if await self.user_repo.exists_by_username(request.username):
            raise UsernameAlreadyExistsError("Username already taken")
        
        # Hash password with Argon2id
        hashed_password = self.security_service.hash_password(request.password)
        
        # Create user
        user = User(
            email=request.email,
            username=request.username,
            password=hashed_password,
            account_type=request.account_type,
            role="user",
            verified=False,
            is_active=True,
            email_verified_at=None
        )
        
        user = await self.user_repo.save(user)
        
        # Generate tokens
        access_token = self.security_service.create_access_token(
            data={"sub": str(user.id), "email": user.email}
        )
        
        token_string, token_hash = self.security_service.create_refresh_token(user.id)
        expires_at = self.security_service.get_refresh_token_expiry()
        
        # Save refresh token
        await self.refresh_token_repo.create(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        await self.session.commit()
        
        # Build response
        token_response = TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=self.security_service.access_token_expire_minutes * 60,
            refresh_token=token_string
        )
        
        user_response = UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            account_type=user.account_type,
            role=user.role,
            verified=user.verified,
            is_active=user.is_active,
            email_verified_at=user.email_verified_at,
            last_login_at=user.last_login_at,
            on_vacation=user.on_vacation,
            powerseller=user.powerseller
        )
        
        return AuthResponse(
            success=True,
            data=token_response,
            user=user_response
        )


class RefreshTokenUseCase:
    """Use case for refreshing access token"""
    
    def __init__(
        self,
        session: AsyncSession,
        security_service: SecurityService
    ):
        """
        Initialize refresh token use case
        
        Args:
            session: Database session
            security_service: Security service instance
        """
        self.session = session
        self.security_service = security_service
        self.user_repo = UserRepository(session)
        self.refresh_token_repo = RefreshTokenRepository(session)
    
    async def execute(
        self,
        refresh_token: str,
        ip_address: str,
        user_agent: Optional[str] = None
    ) -> AuthResponse:
        """
        Execute refresh token use case (token rotation)
        
        Args:
            refresh_token: Refresh token string
            ip_address: Client IP address
            user_agent: Optional user agent string
            
        Returns:
            AuthResponse with new tokens and user data
            
        Raises:
            InvalidRefreshTokenError: If refresh token is invalid or expired
        """
        # Hash the provided token
        token_hash = self.security_service.hash_refresh_token(refresh_token)
        
        # Find token in database
        db_token = await self.refresh_token_repo.get_by_token_hash(token_hash)
        
        if not db_token or not db_token.is_valid():
            raise InvalidRefreshTokenError("Invalid or expired refresh token")
        
        # Get user
        user = await self.user_repo.get_by_id(db_token.user_id)
        if not user or not user.is_active:
            raise InvalidRefreshTokenError("Invalid or expired refresh token")
        
        # Revoke old refresh token (token rotation)
        await self.refresh_token_repo.revoke(db_token.id, reason="Token rotation")
        
        # Generate new tokens
        access_token = self.security_service.create_access_token(
            data={"sub": str(user.id), "email": user.email}
        )
        
        new_token_string, new_token_hash = self.security_service.create_refresh_token(user.id)
        expires_at = self.security_service.get_refresh_token_expiry()
        
        # Save new refresh token
        await self.refresh_token_repo.create(
            user_id=user.id,
            token_hash=new_token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        await self.session.commit()
        
        # Build response
        token_response = TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=self.security_service.access_token_expire_minutes * 60,
            refresh_token=new_token_string
        )
        
        user_response = UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            account_type=user.account_type,
            role=user.role,
            verified=user.verified,
            is_active=user.is_active,
            email_verified_at=user.email_verified_at,
            last_login_at=user.last_login_at,
            on_vacation=user.on_vacation,
            powerseller=user.powerseller
        )
        
        return AuthResponse(
            success=True,
            data=token_response,
            user=user_response
        )


class LogoutUseCase:
    """Use case for user logout"""
    
    def __init__(
        self,
        session: AsyncSession,
        security_service: SecurityService,
        redis_service: RedisService
    ):
        """
        Initialize logout use case
        
        Args:
            session: Database session
            security_service: Security service instance
            redis_service: Redis service instance
        """
        self.session = session
        self.security_service = security_service
        self.redis_service = redis_service
        self.refresh_token_repo = RefreshTokenRepository(session)
    
    async def execute(
        self,
        refresh_token: Optional[str],
        access_token: Optional[str],
        user_id: int
    ) -> bool:
        """
        Execute logout use case
        
        Args:
            refresh_token: Optional refresh token to revoke
            access_token: Access token to blacklist
            user_id: User ID
            
        Returns:
            True if logout successful
        """
        # Revoke all refresh tokens for user
        await self.refresh_token_repo.revoke_all_for_user(user_id)
        
        # Blacklist access token in Redis
        if access_token:
            # Get token expiration from JWT
            payload = self.security_service.verify_access_token(access_token)
            if payload:
                exp = payload.get("exp")
                if exp:
                    from datetime import datetime, timezone
                    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
                    now = datetime.now(timezone.utc)
                    ttl = int((expires_at - now).total_seconds())
                    if ttl > 0:
                        await self.redis_service.blacklist_token(access_token, ttl)
        
        await self.session.commit()
        return True
