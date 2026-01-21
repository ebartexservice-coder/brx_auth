"""
Database and Redis Connection Check Script
Attempts to connect to the database and Redis using current configuration
and prints "OK" or specific error messages.
"""
import asyncio
import sys
import os
from pathlib import Path

# Add parent directory to path to allow imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
import redis.asyncio as aioredis
from app.core.config import get_settings


async def check_database():
    """
    Check database connection
    
    Returns:
        tuple: (success: bool, message: str)
    """
    settings = get_settings()
    
    if not settings.database_url:
        return False, "ERROR: DATABASE_URL not configured"
    
    try:
        # Create async engine
        engine = create_async_engine(
            settings.database_url,
            echo=False,
            pool_pre_ping=True,  # Verify connections before using
            connect_args={
                "connect_timeout": 5
            }
        )
        
        # Test connection
        async with engine.begin() as conn:
            result = await conn.execute(text("SELECT 1"))
            row = result.fetchone()
            if row and row[0] == 1:
                return True, "OK"
            else:
                return False, "ERROR: Database query returned unexpected result"
                
    except Exception as e:
        error_msg = str(e)
        # Provide more specific error messages
        if "authentication failed" in error_msg.lower() or "access denied" in error_msg.lower():
            return False, f"ERROR: Database authentication failed - {error_msg}"
        elif "could not connect" in error_msg.lower() or "connection refused" in error_msg.lower():
            return False, f"ERROR: Cannot connect to database - {error_msg}"
        elif "timeout" in error_msg.lower():
            return False, f"ERROR: Database connection timeout - {error_msg}"
        elif "name or service not known" in error_msg.lower():
            return False, f"ERROR: Database hostname not found - {error_msg}"
        else:
            return False, f"ERROR: Database connection failed - {error_msg}"
    finally:
        try:
            await engine.dispose()
        except:
            pass


async def check_redis():
    """
    Check Redis connection
    
    Returns:
        tuple: (success: bool, message: str)
    """
    settings = get_settings()
    
    if not settings.redis_url:
        return False, "ERROR: REDIS_URL not configured"
    
    redis_client = None
    try:
        # Create Redis connection
        redis_client = await aioredis.from_url(
            settings.redis_url,
            password=settings.redis_password if settings.redis_password else None,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5
        )
        
        # Test connection with PING
        result = await redis_client.ping()
        if result:
            return True, "OK"
        else:
            return False, "ERROR: Redis PING returned False"
            
    except Exception as e:
        error_msg = str(e)
        error_type = type(e).__name__
        
        # Provide specific error messages based on error type and content
        if "connection" in error_type.lower() or "connection" in error_msg.lower():
            if "refused" in error_msg.lower():
                return False, f"ERROR: Redis connection refused - {error_msg}"
            elif "timeout" in error_msg.lower():
                return False, f"ERROR: Redis connection timeout - {error_msg}"
            else:
                return False, f"ERROR: Cannot connect to Redis - {error_msg}"
        elif "authentication" in error_type.lower() or "auth" in error_msg.lower() or "password" in error_msg.lower():
            return False, f"ERROR: Redis authentication failed - {error_msg}"
        elif "name or service not known" in error_msg.lower() or "nodename" in error_msg.lower():
            return False, f"ERROR: Redis hostname not found - {error_msg}"
        else:
            return False, f"ERROR: Redis connection failed - {error_msg}"
    finally:
        if redis_client:
            try:
                await redis_client.close()
            except:
                pass


async def main():
    """
    Main function to check both database and Redis connections
    """
    print("=" * 60)
    print("Database and Redis Connection Check")
    print("=" * 60)
    print()
    
    # Check database
    print("Checking Database Connection...")
    print(f"  DATABASE_URL: {get_settings().database_url[:50]}..." if len(get_settings().database_url) > 50 else f"  DATABASE_URL: {get_settings().database_url}")
    db_success, db_message = await check_database()
    print(f"  Result: {db_message}")
    print()
    
    # Check Redis
    print("Checking Redis Connection...")
    print(f"  REDIS_URL: {get_settings().redis_url}")
    redis_success, redis_message = await check_redis()
    print(f"  Result: {redis_message}")
    print()
    
    # Summary
    print("=" * 60)
    print("Summary:")
    print(f"  Database: {'✓ OK' if db_success else '✗ FAILED'}")
    print(f"  Redis:    {'✓ OK' if redis_success else '✗ FAILED'}")
    print("=" * 60)
    
    # Exit with appropriate code
    if db_success and redis_success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    # Load environment variables from .env if it exists
    from dotenv import load_dotenv
    load_dotenv()
    
    # Run async main
    asyncio.run(main())
