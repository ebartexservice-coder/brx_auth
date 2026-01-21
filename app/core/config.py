"""
Application Configuration
Centralized configuration management using Pydantic Settings
"""
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
import os


class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application
    app_name: str = "auth-service"
    app_env: str = "development"
    debug: bool = False
    log_level: str = "INFO"
    
    # Database
    database_url: str
    
    # JWT Configuration
    jwt_private_key: Optional[str] = None
    jwt_private_key_ssm_path: Optional[str] = None
    jwt_public_key: Optional[str] = None
    jwt_public_key_ssm_path: Optional[str] = None
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    
    # Redis Configuration
    redis_url: str = "redis://localhost:6379/0"
    redis_password: Optional[str] = None
    
    # AWS Configuration
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    
    # Security Settings
    max_login_attempts: int = 5
    login_attempt_window_minutes: int = 15
    account_lockout_minutes: int = 30
    
    # Rate Limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_requests_per_hour: int = 1000
    
    # CORS
    allowed_origins: str = "http://localhost:3000,http://localhost:8080"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.app_env.lower() in ("production", "prod")
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment"""
        return self.app_env.lower() in ("development", "dev")
    
    @property
    def allowed_origins_list(self) -> List[str]:
        """
        Parse comma-separated allowed origins string into list
        
        Returns:
            List of allowed origin URLs
        """
        if not self.allowed_origins:
            return []
        
        # Split by comma and strip whitespace
        origins = [origin.strip() for origin in self.allowed_origins.split(",")]
        # Filter out empty strings
        return [origin for origin in origins if origin]
    
    @property
    def default_allowed_origins(self) -> List[str]:
        """
        Get default allowed origins for production
        
        Returns:
            List of default production origins
        """
        return [
            "https://ebartex.com",
            "https://ebartex.it",
            "https://www.ebartex.com",
            "https://www.ebartex.it"
        ]
    
    def get_allowed_origins(self) -> List[str]:
        """
        Get allowed origins based on environment
        
        Returns:
            List of allowed origin URLs
        """
        if self.is_production:
            # In production, merge configured origins with defaults
            configured = self.allowed_origins_list
            defaults = self.default_allowed_origins
            # Combine and remove duplicates
            combined = list(set(configured + defaults))
            return combined if combined else defaults
        else:
            # In development, use configured origins or defaults
            configured = self.allowed_origins_list
            return configured if configured else ["http://localhost:3000", "http://localhost:8080"]


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance (singleton pattern)
    
    Returns:
        Settings instance
    """
    return Settings()
