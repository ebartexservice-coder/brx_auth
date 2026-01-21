"""
FastAPI Dependencies
Dependency injection for database sessions, services, etc.
"""
from typing import AsyncGenerator
from fastapi import Depends, HTTPException, status, Header
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
import os

from app.infrastructure.security.key_loader import get_key_loader, KeyLoader
from app.core.security import SecurityService
from app.infrastructure.cache.redis_service import RedisService


# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is required")

engine = create_async_engine(
    DATABASE_URL,
    echo=os.getenv("DEBUG", "False").lower() == "true",
    future=True
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for database session
    
    Yields:
        AsyncSession: Database session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Service dependencies
_key_loader = None
_security_service = None
_redis_service = None


def get_key_loader_dependency() -> KeyLoader:
    """
    Dependency for key loader (singleton)
    
    Returns:
        KeyLoader instance
    """
    global _key_loader
    if _key_loader is None:
        _key_loader = get_key_loader()
    return _key_loader


def get_security_service() -> SecurityService:
    """
    Dependency for security service (singleton)
    
    Returns:
        SecurityService instance
    """
    global _security_service
    if _security_service is None:
        key_loader = get_key_loader_dependency()
        _security_service = SecurityService(key_loader)
    return _security_service


async def get_redis_service() -> RedisService:
    """
    Dependency for Redis service (singleton)
    
    Returns:
        RedisService instance
    """
    global _redis_service
    if _redis_service is None:
        _redis_service = RedisService()
        await _redis_service.connect()
    return _redis_service


# Authentication dependencies
async def get_current_user_id(
    authorization: str = Header(..., description="Bearer token"),
    security_service: SecurityService = Depends(get_security_service),
    redis_service: RedisService = Depends(get_redis_service)
) -> int:
    """
    Dependency to get current authenticated user ID from JWT token
    
    Args:
        authorization: Authorization header with Bearer token
        security_service: Security service instance
        redis_service: Redis service instance
        
    Returns:
        User ID
        
    Raises:
        HTTPException: If token is invalid or blacklisted
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format"
        )
    
    token = authorization.replace("Bearer ", "")
    
    # Check if token is blacklisted
    is_blacklisted = await redis_service.is_token_blacklisted(token)
    if is_blacklisted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked"
        )
    
    # Verify token
    payload = security_service.verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    return int(user_id)


async def get_current_user(
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Dependency to get current authenticated user
    
    Args:
        user_id: User ID from token
        db: Database session
        
    Returns:
        User instance
        
    Raises:
        HTTPException: If user not found
    """
    from app.infrastructure.repositories.user_repository import UserRepository
    from app.infrastructure.database.models import User
    
    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    return user


# Startup/shutdown events
async def startup_event():
    """Application startup - initialize Redis connection"""
    redis_service = await get_redis_service()
    await redis_service.connect()


async def shutdown_event():
    """Application shutdown - close Redis connection"""
    global _redis_service
    if _redis_service:
        await _redis_service.disconnect()
