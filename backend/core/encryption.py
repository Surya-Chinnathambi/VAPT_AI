"""
Encryption Utilities
Encrypt/decrypt sensitive data in database
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class EncryptionManager:
    """
    Manage encryption/decryption of sensitive data
    Uses Fernet (symmetric encryption) with key derivation
    """
    
    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize encryption manager
        
        Args:
            encryption_key: Base encryption key (from environment variable)
        """
        if encryption_key is None:
            encryption_key = os.getenv("ENCRYPTION_KEY")
        
        if not encryption_key:
            # Generate a new key for development
            logger.warning("No ENCRYPTION_KEY found, generating temporary key")
            encryption_key = Fernet.generate_key().decode()
            logger.warning(f"Generated temporary encryption key: {encryption_key}")
            logger.warning("Add this to your .env file as ENCRYPTION_KEY")
        
        # Derive a Fernet key from the encryption key
        self.fernet = self._create_fernet(encryption_key)
    
    def _create_fernet(self, password: str) -> Fernet:
        """
        Create a Fernet instance from a password
        """
        # Use a fixed salt (in production, consider using per-field salts)
        salt = b"cybershield_salt_v1"
        
        # Derive a key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string
        
        Args:
            plaintext: The string to encrypt
            
        Returns:
            Encrypted string (base64 encoded)
        """
        if not plaintext:
            return plaintext
        
        try:
            encrypted_bytes = self.fernet.encrypt(plaintext.encode())
            return encrypted_bytes.decode()
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt a string
        
        Args:
            ciphertext: The encrypted string (base64 encoded)
            
        Returns:
            Decrypted plaintext string
        """
        if not ciphertext:
            return ciphertext
        
        try:
            decrypted_bytes = self.fernet.decrypt(ciphertext.encode())
            return decrypted_bytes.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise
    
    def encrypt_dict(self, data: dict, fields_to_encrypt: list) -> dict:
        """
        Encrypt specific fields in a dictionary
        
        Args:
            data: Dictionary containing data
            fields_to_encrypt: List of field names to encrypt
            
        Returns:
            Dictionary with encrypted fields
        """
        encrypted_data = data.copy()
        
        for field in fields_to_encrypt:
            if field in encrypted_data and encrypted_data[field]:
                encrypted_data[field] = self.encrypt(str(encrypted_data[field]))
        
        return encrypted_data
    
    def decrypt_dict(self, data: dict, fields_to_decrypt: list) -> dict:
        """
        Decrypt specific fields in a dictionary
        
        Args:
            data: Dictionary containing encrypted data
            fields_to_decrypt: List of field names to decrypt
            
        Returns:
            Dictionary with decrypted fields
        """
        decrypted_data = data.copy()
        
        for field in fields_to_decrypt:
            if field in decrypted_data and decrypted_data[field]:
                try:
                    decrypted_data[field] = self.decrypt(decrypted_data[field])
                except Exception as e:
                    logger.warning(f"Failed to decrypt field {field}: {str(e)}")
                    # Keep encrypted value if decryption fails
        
        return decrypted_data


# Global encryption manager instance
_encryption_manager: Optional[EncryptionManager] = None


def get_encryption_manager() -> EncryptionManager:
    """
    Get or create the global encryption manager instance
    """
    global _encryption_manager
    
    if _encryption_manager is None:
        _encryption_manager = EncryptionManager()
    
    return _encryption_manager


def encrypt_field(value: str) -> str:
    """
    Convenience function to encrypt a field
    """
    manager = get_encryption_manager()
    return manager.encrypt(value)


def decrypt_field(value: str) -> str:
    """
    Convenience function to decrypt a field
    """
    manager = get_encryption_manager()
    return manager.decrypt(value)


# Fields that should be encrypted in the database
ENCRYPTED_FIELDS = {
    "users": ["api_key", "shodan_api_key", "openai_api_key"],
    "scans": ["results"],  # Scan results may contain sensitive data
    "api_keys": ["key_value"],  # API key values
}


def should_encrypt_field(table: str, field: str) -> bool:
    """
    Check if a field should be encrypted
    """
    return table in ENCRYPTED_FIELDS and field in ENCRYPTED_FIELDS[table]
