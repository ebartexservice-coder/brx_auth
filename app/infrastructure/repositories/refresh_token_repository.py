"""
Refresh Token Repository
Abstracts database access for RefreshToken operations
"""
from typing import Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_

from app.infrastructure.database.models import RefreshToken


class RefreshTokenRepository:
    """Repository for RefreshToken database operations"""
    
    def __init__(self, session: AsyncSession):
        """
        Initialize repository with database session
        
        Args:
            session: Async SQLAlchemy session
        """
        self.session = session
    
    async def create(
        self,
        user_id: int,
        token_hash: str,
        expires_at: datetime,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> RefreshToken:
        """
        Create new refresh token
        
        Args:
            user_id: User ID
            token_hash: SHA256 hash of the token
            expires_at: Token expiration datetime
            ip_address: Optional IP address
            user_agent: Optional user agent string
            
        Returns:
            Created RefreshToken instance
        """
        refresh_token = RefreshToken(
            user_id=user_id,
            token=token_hash,  # Store hash as token for lookup
            token_hash=token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent
        )
        self.session.add(refresh_token)
        await self.session.flush()
        await self.session.refresh(refresh_token)
        return refresh_token
    
    async def get_by_token_hash(self, token_hash: str) -> Optional[RefreshToken]:
        """
        Get refresh token by hash
        
        Args:
            token_hash: SHA256 hash of the token
            
        Returns:
            RefreshToken instance if found, None otherwise
        """
        stmt = select(RefreshToken).where(
            and_(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked_at.is_(None)
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_valid_token(
        self,
        token_hash: str,
        user_id: int
    ) -> Optional[RefreshToken]:
        """
        Get valid (non-expired, non-revoked) refresh token
        
        Args:
            token_hash: SHA256 hash of the token
            user_id: User ID
            
        Returns:
            Valid RefreshToken instance if found, None otherwise
        """
        stmt = select(RefreshToken).where(
            and_(
                RefreshToken.token_hash == token_hash,
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > datetime.now(timezone.utc)
            )
        )
        result = await self.session.execute(stmt)
        token = result.scalar_one_or_none()
        
        if token and token.is_valid():
            return token
        return None
    
    async def revoke(self, token_id: int, reason: Optional[str] = None) -> bool:
        """
        Revoke refresh token
        
        Args:
            token_id: Refresh token ID
            reason: Optional revocation reason
            
        Returns:
            True if revocation successful, False otherwise
        """
        stmt = (
            update(RefreshToken)
            .where(RefreshToken.id == token_id)
            .values(
                revoked_at=datetime.now(timezone.utc),
                revoked_reason=reason or "User logout"
            )
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0
    
    async def revoke_all_for_user(self, user_id: int) -> int:
        """
        Revoke all refresh tokens for a user
        
        Args:
            user_id: User ID
            
        Returns:
            Number of tokens revoked
        """
        stmt = (
            update(RefreshToken)
            .where(
                and_(
                    RefreshToken.user_id == user_id,
                    RefreshToken.revoked_at.is_(None)
                )
            )
            .values(
                revoked_at=datetime.now(timezone.utc),
                revoked_reason="User logout - all tokens revoked"
            )
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount
    
    async def update_last_used(self, token_id: int) -> bool:
        """
        Update token's last used timestamp
        
        Args:
            token_id: Refresh token ID
            
        Returns:
            True if update successful, False otherwise
        """
        stmt = (
            update(RefreshToken)
            .where(RefreshToken.id == token_id)
            .values(last_used_at=datetime.now(timezone.utc))
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0
