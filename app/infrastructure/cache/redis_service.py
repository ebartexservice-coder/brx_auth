"""
Redis Service
Handles caching, token blacklisting, and rate limiting
"""
import json
from typing import Optional, Any
from datetime import datetime, timedelta, timezone
import redis.asyncio as aioredis
import os
import logging

logger = logging.getLogger(__name__)


class RedisService:
    """
    Redis service for caching, token blacklisting, and rate limiting
    Implements "Leaky Bucket" algorithm for rate limiting
    """
    
    def __init__(self):
        """Initialize Redis connection"""
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        redis_password = os.getenv("REDIS_PASSWORD")
        
        # Parse Redis URL
        self.redis_client: Optional[aioredis.Redis] = None
        self._redis_url = redis_url
        self._redis_password = redis_password
        
        # Rate limiting configuration
        self.rate_limit_requests_per_minute = int(
            os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60")
        )
        self.rate_limit_requests_per_hour = int(
            os.getenv("RATE_LIMIT_REQUESTS_PER_HOUR", "1000")
        )
    
    async def connect(self) -> None:
        """Establish Redis connection"""
        try:
            self.redis_client = await aioredis.from_url(
                self._redis_url,
                password=self._redis_password if self._redis_password else None,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            # Test connection
            await self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    async def disconnect(self) -> None:
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
            logger.info("Redis connection closed")
    
    async def is_connected(self) -> bool:
        """Check if Redis is connected"""
        if not self.redis_client:
            return False
        try:
            await self.redis_client.ping()
            return True
        except Exception:
            return False
    
    # Token Blacklist Operations
    
    async def blacklist_token(
        self,
        token: str,
        expires_in_seconds: int
    ) -> bool:
        """
        Add access token to blacklist (for logout)
        
        Args:
            token: JWT access token
            expires_in_seconds: Token expiration time in seconds
            
        Returns:
            True if successful, False otherwise
        """
        if not self.redis_client:
            await self.connect()
        
        try:
            # Store token hash in blacklist with TTL = token expiration
            token_key = f"blacklist:token:{token}"
            await self.redis_client.setex(
                token_key,
                expires_in_seconds,
                "1"  # Value doesn't matter, key existence is what counts
            )
            return True
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e}")
            return False
    
    async def is_token_blacklisted(self, token: str) -> bool:
        """
        Check if access token is blacklisted
        
        Args:
            token: JWT access token
            
        Returns:
            True if token is blacklisted, False otherwise
        """
        if not self.redis_client:
            await self.connect()
        
        try:
            token_key = f"blacklist:token:{token}"
            exists = await self.redis_client.exists(token_key)
            return exists > 0
        except Exception as e:
            logger.error(f"Failed to check token blacklist: {e}")
            # Fail open - if Redis is down, don't block requests
            return False
    
    # Rate Limiting Operations (Leaky Bucket Algorithm)
    
    async def check_rate_limit(
        self,
        identifier: str,
        event_type: str = "api_request",
        window_minutes: int = 1
    ) -> tuple[bool, int, int]:
        """
        Check rate limit using Leaky Bucket algorithm
        
        Args:
            identifier: IP address, email, or user_id
            event_type: Type of event (login_attempt, api_request, etc.)
            window_minutes: Time window in minutes
            
        Returns:
            Tuple of (is_allowed, current_count, limit)
        """
        if not self.redis_client:
            await self.connect()
        
        try:
            # Determine limit based on window
            if window_minutes == 1:
                limit = self.rate_limit_requests_per_minute
            elif window_minutes == 60:
                limit = self.rate_limit_requests_per_hour
            else:
                limit = self.rate_limit_requests_per_minute
            
            # Create key for this identifier and event type
            key = f"rate_limit:{event_type}:{identifier}:{window_minutes}"
            
            # Get current count
            current_count = await self.redis_client.get(key)
            current_count = int(current_count) if current_count else 0
            
            # Check if limit exceeded
            if current_count >= limit:
                return False, current_count, limit
            
            # Increment count with TTL
            pipe = self.redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_minutes * 60)
            results = await pipe.execute()
            
            new_count = results[0]
            return True, new_count, limit
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            # Fail open - if Redis is down, allow request
            return True, 0, limit
    
    async def reset_rate_limit(
        self,
        identifier: str,
        event_type: str = "api_request",
        window_minutes: int = 1
    ) -> bool:
        """
        Reset rate limit counter
        
        Args:
            identifier: IP address, email, or user_id
            event_type: Type of event
            window_minutes: Time window in minutes
            
        Returns:
            True if successful, False otherwise
        """
        if not self.redis_client:
            await self.connect()
        
        try:
            key = f"rate_limit:{event_type}:{identifier}:{window_minutes}"
            await self.redis_client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Failed to reset rate limit: {e}")
            return False
    
    # Cache Operations
    
    async def get_cache(self, key: str) -> Optional[Any]:
        """
        Get value from cache
        
        Args:
            key: Cache key
            
        Returns:
            Cached value if exists, None otherwise
        """
        if not self.redis_client:
            await self.connect()
        
        try:
            value = await self.redis_client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"Cache get failed: {e}")
            return None
    
    async def set_cache(
        self,
        key: str,
        value: Any,
        ttl_seconds: int = 3600
    ) -> bool:
        """
        Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache (must be JSON serializable)
            ttl_seconds: Time to live in seconds
            
        Returns:
            True if successful, False otherwise
        """
        if not self.redis_client:
            await self.connect()
        
        try:
            serialized = json.dumps(value)
            await self.redis_client.setex(key, ttl_seconds, serialized)
            return True
        except Exception as e:
            logger.error(f"Cache set failed: {e}")
            return False
    
    async def delete_cache(self, key: str) -> bool:
        """
        Delete value from cache
        
        Args:
            key: Cache key
            
        Returns:
            True if successful, False otherwise
        """
        if not self.redis_client:
            await self.connect()
        
        try:
            await self.redis_client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Cache delete failed: {e}")
            return False
    
    async def increment_counter(
        self,
        key: str,
        ttl_seconds: Optional[int] = None
    ) -> int:
        """
        Increment counter (for brute force tracking)
        
        Args:
            key: Counter key
            ttl_seconds: Optional TTL for the counter
            
        Returns:
            New counter value
        """
        if not self.redis_client:
            await self.connect()
        
        try:
            pipe = self.redis_client.pipeline()
            pipe.incr(key)
            if ttl_seconds:
                pipe.expire(key, ttl_seconds)
            results = await pipe.execute()
            return results[0]
        except Exception as e:
            logger.error(f"Counter increment failed: {e}")
            return 0
    
    async def get_counter(self, key: str) -> int:
        """
        Get counter value
        
        Args:
            key: Counter key
            
        Returns:
            Counter value (0 if not found)
        """
        if not self.redis_client:
            await self.connect()
        
        try:
            value = await self.redis_client.get(key)
            return int(value) if value else 0
        except Exception as e:
            logger.error(f"Counter get failed: {e}")
            return 0
    
    async def reset_counter(self, key: str) -> bool:
        """
        Reset counter
        
        Args:
            key: Counter key
            
        Returns:
            True if successful, False otherwise
        """
        if not self.redis_client:
            await self.connect()
        
        try:
            await self.redis_client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Counter reset failed: {e}")
            return False
