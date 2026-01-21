"""
User Repository
Abstracts database access for User operations
"""
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.infrastructure.database.models import User


class UserRepository:
    """Repository for User database operations"""
    
    def __init__(self, session: AsyncSession):
        """
        Initialize repository with database session
        
        Args:
            session: Async SQLAlchemy session
        """
        self.session = session
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email address
        
        Args:
            email: User email address
            
        Returns:
            User instance if found, None otherwise
        """
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """
        Get user by ID
        
        Args:
            user_id: User ID
            
        Returns:
            User instance if found, None otherwise
        """
        stmt = select(User).where(User.id == user_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username
        
        Args:
            username: Username
            
        Returns:
            User instance if found, None otherwise
        """
        stmt = select(User).where(User.username == username)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def save(self, user: User) -> User:
        """
        Save user (create or update)
        
        Args:
            user: User instance to save
            
        Returns:
            Saved User instance
        """
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        return user
    
    async def update_password(self, user_id: int, new_hash: str) -> bool:
        """
        Update user password hash
        
        Args:
            user_id: User ID
            new_hash: New password hash
            
        Returns:
            True if update successful, False otherwise
        """
        stmt = (
            update(User)
            .where(User.id == user_id)
            .values(password=new_hash)
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0
    
    async def update_last_login(self, user_id: int) -> bool:
        """
        Update user's last login timestamp
        
        Args:
            user_id: User ID
            
        Returns:
            True if update successful, False otherwise
        """
        from datetime import datetime, timezone
        stmt = (
            update(User)
            .where(User.id == user_id)
            .values(last_login_at=datetime.now(timezone.utc))
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0
    
    async def exists_by_email(self, email: str) -> bool:
        """
        Check if user with email exists
        
        Args:
            email: Email address to check
            
        Returns:
            True if user exists, False otherwise
        """
        user = await self.get_by_email(email)
        return user is not None
    
    async def exists_by_username(self, username: str) -> bool:
        """
        Check if user with username exists
        
        Args:
            username: Username to check
            
        Returns:
            True if user exists, False otherwise
        """
        user = await self.get_by_username(username)
        return user is not None
