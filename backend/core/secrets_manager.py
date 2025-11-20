"""
Secrets Management
Integration with AWS Secrets Manager for secure credential storage
"""

import os
import json
import logging
from typing import Optional, Dict, Any
from functools import lru_cache

logger = logging.getLogger(__name__)

# Try to import boto3 (AWS SDK)
try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    logger.warning("boto3 not installed. AWS Secrets Manager integration disabled.")


class SecretsManager:
    """
    Manage secrets from AWS Secrets Manager or environment variables
    """
    
    def __init__(self, use_aws: bool = None, region: str = None):
        """
        Initialize secrets manager
        
        Args:
            use_aws: Whether to use AWS Secrets Manager (default: check environment)
            region: AWS region (default: from environment or us-east-1)
        """
        if use_aws is None:
            use_aws = os.getenv("USE_AWS_SECRETS", "false").lower() == "true"
        
        self.use_aws = use_aws and AWS_AVAILABLE
        
        if self.use_aws:
            self.region = region or os.getenv("AWS_REGION", "us-east-1")
            self.client = boto3.client(
                service_name='secretsmanager',
                region_name=self.region
            )
            logger.info(f"AWS Secrets Manager initialized (region: {self.region})")
        else:
            self.client = None
            logger.info("Using environment variables for secrets")
    
    @lru_cache(maxsize=32)
    def get_secret(self, secret_name: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a secret value
        
        Args:
            secret_name: Name of the secret
            default: Default value if secret not found
            
        Returns:
            Secret value or default
        """
        if self.use_aws and self.client:
            try:
                response = self.client.get_secret_value(SecretId=secret_name)
                
                # Secrets can be stored as string or binary
                if 'SecretString' in response:
                    return response['SecretString']
                else:
                    # Binary secret (base64 encoded)
                    import base64
                    return base64.b64decode(response['SecretBinary']).decode('utf-8')
                    
            except ClientError as e:
                error_code = e.response['Error']['Code']
                
                if error_code == 'ResourceNotFoundException':
                    logger.warning(f"Secret '{secret_name}' not found in AWS Secrets Manager")
                elif error_code == 'InvalidRequestException':
                    logger.error(f"Invalid request for secret '{secret_name}'")
                elif error_code == 'InvalidParameterException':
                    logger.error(f"Invalid parameter for secret '{secret_name}'")
                else:
                    logger.error(f"Error retrieving secret '{secret_name}': {str(e)}")
                
                # Fall back to environment variable
                return os.getenv(secret_name, default)
            
            except Exception as e:
                logger.error(f"Unexpected error retrieving secret '{secret_name}': {str(e)}")
                return os.getenv(secret_name, default)
        
        else:
            # Use environment variables
            return os.getenv(secret_name, default)
    
    def get_secret_dict(self, secret_name: str) -> Dict[str, Any]:
        """
        Get a secret that contains JSON data
        
        Args:
            secret_name: Name of the secret
            
        Returns:
            Dictionary of secret values
        """
        secret_string = self.get_secret(secret_name)
        
        if secret_string:
            try:
                return json.loads(secret_string)
            except json.JSONDecodeError:
                logger.error(f"Secret '{secret_name}' is not valid JSON")
                return {}
        
        return {}
    
    def create_secret(self, secret_name: str, secret_value: str, description: str = "") -> bool:
        """
        Create a new secret in AWS Secrets Manager
        
        Args:
            secret_name: Name of the secret
            secret_value: Value to store
            description: Description of the secret
            
        Returns:
            True if successful, False otherwise
        """
        if not self.use_aws or not self.client:
            logger.warning("AWS Secrets Manager not enabled. Cannot create secret.")
            return False
        
        try:
            self.client.create_secret(
                Name=secret_name,
                SecretString=secret_value,
                Description=description
            )
            logger.info(f"Created secret '{secret_name}'")
            
            # Clear cache
            self.get_secret.cache_clear()
            
            return True
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceExistsException':
                logger.warning(f"Secret '{secret_name}' already exists")
                return self.update_secret(secret_name, secret_value)
            else:
                logger.error(f"Error creating secret '{secret_name}': {str(e)}")
                return False
        
        except Exception as e:
            logger.error(f"Unexpected error creating secret '{secret_name}': {str(e)}")
            return False
    
    def update_secret(self, secret_name: str, secret_value: str) -> bool:
        """
        Update an existing secret
        
        Args:
            secret_name: Name of the secret
            secret_value: New value
            
        Returns:
            True if successful, False otherwise
        """
        if not self.use_aws or not self.client:
            logger.warning("AWS Secrets Manager not enabled. Cannot update secret.")
            return False
        
        try:
            self.client.update_secret(
                SecretId=secret_name,
                SecretString=secret_value
            )
            logger.info(f"Updated secret '{secret_name}'")
            
            # Clear cache
            self.get_secret.cache_clear()
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating secret '{secret_name}': {str(e)}")
            return False
    
    def rotate_secret(self, secret_name: str) -> bool:
        """
        Trigger rotation for a secret
        
        Args:
            secret_name: Name of the secret
            
        Returns:
            True if successful, False otherwise
        """
        if not self.use_aws or not self.client:
            logger.warning("AWS Secrets Manager not enabled. Cannot rotate secret.")
            return False
        
        try:
            self.client.rotate_secret(SecretId=secret_name)
            logger.info(f"Triggered rotation for secret '{secret_name}'")
            
            # Clear cache
            self.get_secret.cache_clear()
            
            return True
            
        except Exception as e:
            logger.error(f"Error rotating secret '{secret_name}': {str(e)}")
            return False


# Global secrets manager instance
_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager() -> SecretsManager:
    """
    Get or create the global secrets manager instance
    """
    global _secrets_manager
    
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    
    return _secrets_manager


def get_secret(secret_name: str, default: Optional[str] = None) -> Optional[str]:
    """
    Convenience function to get a secret
    """
    manager = get_secrets_manager()
    return manager.get_secret(secret_name, default)


# Common secret names
class SecretNames:
    """
    Centralized secret name constants
    """
    DATABASE_URL = "DATABASE_URL"
    REDIS_URL = "REDIS_URL"
    JWT_SECRET_KEY = "JWT_SECRET_KEY"
    ENCRYPTION_KEY = "ENCRYPTION_KEY"
    OPENAI_API_KEY = "OPENAI_API_KEY"
    SHODAN_API_KEY = "SHODAN_API_KEY"
    SENTRY_DSN = "SENTRY_DSN"
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY_ID"
    AWS_SECRET_KEY = "AWS_SECRET_ACCESS_KEY"
    SMTP_PASSWORD = "SMTP_PASSWORD"
