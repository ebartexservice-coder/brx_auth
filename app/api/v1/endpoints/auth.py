"""
Authentication API Endpoints
FastAPI routes for authentication operations
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    RefreshTokenRequest,
    AuthResponse,
    LogoutResponse
)
from app.api.dependencies import (
    get_db,
    get_security_service,
    get_redis_service,
    get_current_user_id
)
from app.application.use_cases.auth import (
    LoginUseCase,
    RegisterUseCase,
    RefreshTokenUseCase,
    LogoutUseCase,
    InvalidCredentialsError,
    UserInactiveError,
    AccountLockedError,
    EmailAlreadyExistsError,
    UsernameAlreadyExistsError,
    InvalidRefreshTokenError,
    AuthenticationError
)
from app.core.security import SecurityService
from app.infrastructure.cache.redis_service import RedisService
from app.infrastructure.database.models import User

router = APIRouter(prefix="/auth", tags=["authentication"])


def get_client_ip(request: Request) -> str:
    """
    Extract client IP address from request
    
    Args:
        request: FastAPI request object
        
    Returns:
        Client IP address
    """
    # Check for forwarded IP (behind proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    if request.client:
        return request.client.host
    
    return "unknown"


@router.post("/login", response_model=AuthResponse, status_code=status.HTTP_200_OK)
async def login(
    request: LoginRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    security_service: SecurityService = Depends(get_security_service),
    redis_service: RedisService = Depends(get_redis_service)
):
    """
    User login endpoint
    
    Returns access token and refresh token on successful authentication.
    Supports automatic password migration from Bcrypt (legacy) to Argon2id.
    
    - **email**: User email address
    - **password**: User password (minimum 6 characters)
    """
    try:
        ip_address = get_client_ip(http_request)
        user_agent = http_request.headers.get("User-Agent")
        
        use_case = LoginUseCase(db, security_service, redis_service)
        result = await use_case.execute(request, ip_address, user_agent)
        
        return result
        
    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except UserInactiveError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except AccountLockedError as e:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=str(e)
        )
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    security_service: SecurityService = Depends(get_security_service)
):
    """
    User registration endpoint
    
    Creates a new user account and returns access token and refresh token.
    
    - **username**: Unique username (3-255 characters)
    - **email**: Unique email address
    - **password**: Password (minimum 8 characters, must contain letter and number)
    - **password_confirmation**: Must match password
    - **account_type**: "personal" or "private" (default: "personal")
    """
    try:
        ip_address = get_client_ip(http_request)
        user_agent = http_request.headers.get("User-Agent")
        
        use_case = RegisterUseCase(db, security_service)
        result = await use_case.execute(request, ip_address, user_agent)
        
        return result
        
    except EmailAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )
    except UsernameAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/refresh", response_model=AuthResponse, status_code=status.HTTP_200_OK)
async def refresh(
    request: RefreshTokenRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    security_service: SecurityService = Depends(get_security_service)
):
    """
    Refresh access token endpoint
    
    Rotates refresh token (revokes old, issues new) and returns new access token.
    Implements token rotation for enhanced security.
    
    - **refresh_token**: Valid refresh token
    """
    try:
        ip_address = get_client_ip(http_request)
        user_agent = http_request.headers.get("User-Agent")
        
        use_case = RefreshTokenUseCase(db, security_service)
        result = await use_case.execute(request.refresh_token, ip_address, user_agent)
        
        return result
        
    except InvalidRefreshTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/logout", response_model=LogoutResponse, status_code=status.HTTP_200_OK)
async def logout(
    request: Optional[RefreshTokenRequest] = None,
    authorization: Optional[str] = Header(None),
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
    security_service: SecurityService = Depends(get_security_service),
    redis_service: RedisService = Depends(get_redis_service)
):
    """
    User logout endpoint
    
    Revokes all refresh tokens for the user and blacklists the current access token.
    
    - **refresh_token**: Optional refresh token to revoke (if not provided, all tokens are revoked)
    - **Authorization**: Bearer token (access token to blacklist)
    """
    try:
        # Extract access token from authorization header
        access_token = None
        if authorization and authorization.startswith("Bearer "):
            access_token = authorization.replace("Bearer ", "")
        
        # Get refresh token from request body if provided
        refresh_token = request.refresh_token if request else None
        
        use_case = LogoutUseCase(db, security_service, redis_service)
        await use_case.execute(refresh_token, access_token, user_id)
        
        return LogoutResponse(
            success=True,
            message="Logout effettuato con successo"
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.get("/me", response_model=dict, status_code=status.HTTP_200_OK)
async def get_current_user_info(
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current authenticated user information
    
    Returns user data from the JWT token.
    """
    from app.infrastructure.repositories.user_repository import UserRepository
    from app.domain.schemas.auth import UserResponse
    
    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
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
    ).model_dump()
