"""
RSA Key Loader Service
Loads RSA keys from environment variables (which will come from AWS SSM)
Caches keys in memory for performance
"""
import os
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)


class KeyLoader:
    """
    Service to load and cache RSA keys from environment variables
    Keys are expected to be in PEM format (can be loaded from AWS SSM)
    """
    
    def __init__(self):
        """Initialize key loader and load keys"""
        self._private_key: Optional[rsa.RSAPrivateKey] = None
        self._public_key: Optional[rsa.RSAPublicKey] = None
        self._load_keys()
    
    def _load_keys(self) -> None:
        """
        Load RSA keys from environment variables
        Supports both private key only (public key derived) or both keys
        """
        # Try to load private key
        private_key_pem = os.getenv("JWT_PRIVATE_KEY")
        
        if not private_key_pem:
            logger.warning(
                "JWT_PRIVATE_KEY not found in environment. "
                "JWT signing will fail. Set JWT_PRIVATE_KEY or use AWS SSM."
            )
            return
        
        try:
            # Load private key
            self._private_key = serialization.load_pem_private_key(
                private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
                password=None,  # No password protection for env-based keys
                backend=default_backend()
            )
            
            # Derive public key from private key
            self._public_key = self._private_key.public_key()
            
            logger.info("RSA keys loaded successfully from environment")
            
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
        Reload keys from environment (useful for key rotation)
        """
        logger.info("Reloading RSA keys from environment")
        self._private_key = None
        self._public_key = None
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
