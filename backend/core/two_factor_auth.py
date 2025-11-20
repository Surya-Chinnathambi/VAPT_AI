"""
Two-Factor Authentication (2FA)
TOTP-based 2FA using pyotp
"""

import pyotp
import qrcode
import io
import base64
from typing import Optional, Tuple
from pydantic import BaseModel
import secrets
import logging

logger = logging.getLogger(__name__)


class TwoFactorAuth:
    """
    Manage TOTP-based two-factor authentication
    """
    
    @staticmethod
    def generate_secret() -> str:
        """
        Generate a random base32 secret for TOTP
        
        Returns:
            Base32-encoded secret string
        """
        return pyotp.random_base32()
    
    @staticmethod
    def get_totp_uri(secret: str, user_email: str, issuer: str = "CyberShield AI") -> str:
        """
        Get provisioning URI for QR code
        
        Args:
            secret: Base32 secret
            user_email: User's email address
            issuer: Application name
            
        Returns:
            Provisioning URI
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=user_email, issuer_name=issuer)
    
    @staticmethod
    def generate_qr_code(uri: str) -> str:
        """
        Generate QR code image from provisioning URI
        
        Args:
            uri: Provisioning URI
            
        Returns:
            Base64-encoded PNG image
        """
        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Generate image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    @staticmethod
    def verify_totp(secret: str, token: str, window: int = 1) -> bool:
        """
        Verify a TOTP token
        
        Args:
            secret: User's Base32 secret
            token: 6-digit TOTP code from user
            window: Number of time windows to check (default 1 = ±30 seconds)
            
        Returns:
            True if valid, False otherwise
        """
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=window)
        except Exception as e:
            logger.error(f"TOTP verification error: {str(e)}")
            return False
    
    @staticmethod
    def get_current_totp(secret: str) -> str:
        """
        Get the current TOTP code (for testing/display)
        
        Args:
            secret: Base32 secret
            
        Returns:
            Current 6-digit code
        """
        totp = pyotp.TOTP(secret)
        return totp.now()
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> list[str]:
        """
        Generate backup codes for account recovery
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()
            # Format as XXXX-XXXX for readability
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        
        return codes


class TwoFactorSetup(BaseModel):
    """Response model for 2FA setup"""
    secret: str
    qr_code: str
    backup_codes: list[str]
    manual_entry_key: str


class TwoFactorVerify(BaseModel):
    """Request model for 2FA verification"""
    token: str


def setup_2fa_for_user(user_email: str) -> TwoFactorSetup:
    """
    Set up 2FA for a user
    
    Args:
        user_email: User's email address
        
    Returns:
        Setup information including QR code and backup codes
    """
    # Generate secret
    secret = TwoFactorAuth.generate_secret()
    
    # Generate QR code
    uri = TwoFactorAuth.get_totp_uri(secret, user_email)
    qr_code = TwoFactorAuth.generate_qr_code(uri)
    
    # Generate backup codes
    backup_codes = TwoFactorAuth.generate_backup_codes()
    
    return TwoFactorSetup(
        secret=secret,
        qr_code=qr_code,
        backup_codes=backup_codes,
        manual_entry_key=secret  # For manual entry in authenticator apps
    )


def verify_2fa_token(secret: str, token: str, backup_codes: Optional[list[str]] = None) -> Tuple[bool, Optional[str]]:
    """
    Verify a 2FA token (TOTP or backup code)
    
    Args:
        secret: User's TOTP secret
        token: Token to verify (6-digit TOTP or backup code)
        backup_codes: List of unused backup codes
        
    Returns:
        Tuple of (is_valid, used_backup_code)
    """
    # Try TOTP first
    if TwoFactorAuth.verify_totp(secret, token):
        return True, None
    
    # Try backup codes
    if backup_codes:
        # Remove hyphens and spaces for comparison
        normalized_token = token.replace("-", "").replace(" ", "").upper()
        
        for backup_code in backup_codes:
            normalized_backup = backup_code.replace("-", "").replace(" ", "").upper()
            
            if normalized_token == normalized_backup:
                return True, backup_code
    
    return False, None
