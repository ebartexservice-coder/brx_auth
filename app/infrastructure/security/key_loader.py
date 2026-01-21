"""
RSA Key Loader Service
Loads RSA keys from environment variables or AWS SSM Parameter Store
Caches keys in memory for performance
"""
import os
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

# Try to import boto3 (optional dependency)
try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    logger.warning("boto3 not available. AWS SSM integration disabled.")


class KeyLoader:
    """
    Service to load and cache RSA keys from environment variables or AWS SSM
    Keys are expected to be in PEM format
    """
    
    def __init__(self):
        """Initialize key loader and load keys"""
        self._private_key: Optional[rsa.RSAPrivateKey] = None
        self._public_key: Optional[rsa.RSAPublicKey] = None
        self._ssm_client = None
        self._load_keys()
    
    def _get_ssm_client(self):
        """
        Get or create SSM client
        
        Returns:
            boto3 SSM client or None if not available
        """
        if not BOTO3_AVAILABLE:
            return None
        
        if self._ssm_client is None:
            try:
                # Get AWS configuration from environment
                region = os.getenv("AWS_REGION", "us-east-1")
                access_key = os.getenv("AWS_ACCESS_KEY_ID")
                secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
                
                # Create SSM client
                if access_key and secret_key:
                    self._ssm_client = boto3.client(
                        "ssm",
                        region_name=region,
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key
                    )
                else:
                    # Use default credentials (IAM role, etc.)
                    self._ssm_client = boto3.client("ssm", region_name=region)
                
                logger.info(f"SSM client initialized for region: {region}")
                
            except Exception as e:
                logger.error(f"Failed to initialize SSM client: {e}", exc_info=True)
                return None
        
        return self._ssm_client
    
    def _fetch_from_ssm(self, parameter_path: str) -> Optional[str]:
        """
        Fetch parameter from AWS SSM Parameter Store
        
        Args:
            parameter_path: SSM parameter path
            
        Returns:
            Parameter value as string, or None if not found
        """
        ssm_client = self._get_ssm_client()
        if not ssm_client:
            return None
        
        try:
            response = ssm_client.get_parameter(
                Name=parameter_path,
                WithDecryption=True  # Decrypt SecureString parameters
            )
            return response["Parameter"]["Value"]
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ParameterNotFound":
                logger.warning(f"SSM parameter not found: {parameter_path}")
            elif error_code == "AccessDeniedException":
                logger.error(
                    f"Access denied to SSM parameter {parameter_path}. "
                    "Check IAM permissions or AWS credentials."
                )
            elif error_code == "InvalidKeyId":
                logger.error(f"Invalid SSM parameter path: {parameter_path}")
            else:
                logger.error(
                    f"Failed to fetch SSM parameter {parameter_path}: {e} "
                    f"(Error Code: {error_code})"
                )
            return None
        except BotoCoreError as e:
            logger.error(
                f"AWS service error fetching SSM parameter {parameter_path}: {e}. "
                "Check AWS credentials and network connectivity."
            )
            return None
        except Exception as e:
            logger.error(
                f"Unexpected error fetching SSM parameter {parameter_path}: {e}",
                exc_info=True
            )
            return None
    
    def _is_production(self) -> bool:
        """
        Check if running in production environment by checking APP_ENV directly
        
        Returns:
            True if APP_ENV is 'production' or 'prod', False otherwise
        """
        app_env = os.getenv("APP_ENV", "").lower()
        return app_env in ("production", "prod")
    
    def _load_keys(self) -> None:
        """
        Load RSA keys from environment variables or AWS SSM
        Priority: 1. Environment variables, 2. AWS SSM (if production)
        """
        # Step 1: Try to load from environment variables first
        private_key_pem = os.getenv("JWT_PRIVATE_KEY")
        public_key_pem = os.getenv("JWT_PUBLIC_KEY")
        
        # Step 2: If not in env and in production, try SSM
        if not private_key_pem and self._is_production():
            # Use default SSM paths for production
            private_key_ssm_path = os.getenv(
                "JWT_PRIVATE_KEY_SSM_PATH",
                "/prod/card-refinery/jwt_private_key"
            )
            public_key_ssm_path = os.getenv(
                "JWT_PUBLIC_KEY_SSM_PATH",
                "/prod/card-refinery/jwt_public_key"
            )
            
            logger.info(f"Production environment detected. Attempting to load keys from SSM: {private_key_ssm_path}")
            
            try:
                private_key_pem = self._fetch_from_ssm(private_key_ssm_path)
                if not public_key_pem:
                    public_key_pem = self._fetch_from_ssm(public_key_ssm_path)
            except Exception as e:
                logger.error(f"Failed to load keys from SSM: {e}", exc_info=True)
                # Continue to check if keys were loaded, will fail gracefully below if not
        
        if not private_key_pem:
            logger.error(
                "JWT_PRIVATE_KEY not found in environment or SSM. "
                "JWT signing will fail. Set JWT_PRIVATE_KEY or configure SSM paths."
            )
            return
        
        try:
            # Load private key
            self._private_key = serialization.load_pem_private_key(
                private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            # Load or derive public key
            if public_key_pem:
                # Load public key from SSM/env if provided
                try:
                    public_key_bytes = (
                        public_key_pem.encode() if isinstance(public_key_pem, str) 
                        else public_key_pem
                    )
                    self._public_key = serialization.load_pem_public_key(
                        public_key_bytes,
                        backend=default_backend()
                    )
                    logger.info("RSA keys loaded successfully (private + public from source)")
                except Exception as e:
                    logger.warning(f"Failed to load public key, deriving from private: {e}")
                    # Fallback: derive from private key
                    self._public_key = self._private_key.public_key()
            else:
                # Derive public key from private key
                self._public_key = self._private_key.public_key()
                logger.info("RSA keys loaded successfully (public key derived from private)")
            
        except Exception as e:
            logger.error(f"Failed to load RSA keys: {e}", exc_info=True)
            raise ValueError(f"Invalid RSA private key format: {e}")
    
    def get_private_key(self) -> Optional[bytes]:
        """
        Get private key in PEM format for JWT signing
        
        Returns:
            Private key bytes in PEM format, or None if not loaded
        """
        if not self._private_key:
            return None
        
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def get_public_key(self) -> Optional[bytes]:
        """
        Get public key in PEM format for JWT verification
        
        Returns:
            Public key bytes in PEM format, or None if not loaded
        """
        if not self._public_key:
            return None
        
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def reload_keys(self) -> None:
        """
        Reload keys from environment or SSM (useful for key rotation)
        """
        logger.info("Reloading RSA keys from environment/SSM")
        self._private_key = None
        self._public_key = None
        self._ssm_client = None  # Reset SSM client to force re-initialization
        self._load_keys()
    
    def is_configured(self) -> bool:
        """
        Check if keys are properly configured
        
        Returns:
            True if both keys are loaded, False otherwise
        """
        return self._private_key is not None and self._public_key is not None


# Global key loader instance (singleton pattern)
_key_loader_instance: Optional[KeyLoader] = None


def get_key_loader() -> KeyLoader:
    """
    Get or create global KeyLoader instance
    
    Returns:
        KeyLoader instance
    """
    global _key_loader_instance
    if _key_loader_instance is None:
        _key_loader_instance = KeyLoader()
    return _key_loader_instance
