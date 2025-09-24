"""
KMS Provider implementations for AWS KMS and Google Cloud KMS.
"""

import hashlib
import re
from abc import ABC, abstractmethod
from io import BufferedReader, BytesIO, TextIOWrapper
from pyasn1_modules.rfc3279 import RSAPublicKey
from pyasn1_modules.rfc5280 import SubjectPublicKeyInfo
from pyasn1.codec.der import decoder
from time import time
from datetime import datetime


class KMSProvider(ABC):
    """Abstract base class for KMS providers."""
    
    @abstractmethod
    def get_public_key_info(self, key_id):
        """
        Get public key information from KMS.
        
        Returns:
            dict: Contains 'public_key_der', 'key_spec', 'creation_date', 'arn'
        """
        pass
    
    @abstractmethod
    def get_key_tags(self, key_id):
        """
        Get key tags/labels from KMS.
        
        Returns:
            dict: Tags as key-value pairs
        """
        pass
    
    @abstractmethod
    def sign_digest(self, key_id, digest, hash_length):
        """
        Sign a digest using KMS.
        
        Args:
            key_id: Key identifier
            digest: The digest to sign
            hash_length: Hash algorithm length (256, 384, 512)
            
        Returns:
            int: Signature as integer
        """
        pass
    
    @staticmethod
    def detect_provider(key_id):
        """
        Detect KMS provider based on key ID format.
        
        Args:
            key_id (str): Key identifier
            
        Returns:
            str: 'aws' or 'gcp'
        """
        # AWS KMS key patterns
        if (re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', key_id) or
            key_id.startswith('arn:aws:kms:') or 
            key_id.startswith('alias/')):
            return 'aws'
        
        # Google Cloud KMS key patterns  
        if (key_id.startswith('projects/') and 
            ('locations/' in key_id or 'keyRings/' in key_id or 'cryptoKeys/' in key_id)):
            return 'gcp'
            
        # Default to AWS for backward compatibility
        return 'aws'


class AWSKMSProvider(KMSProvider):
    """AWS KMS provider implementation."""
    
    def __init__(self, kms_client=None):
        if kms_client is None:
            from botocore import session as aws
            session = aws.get_session()
            self.kms_client = session.create_client('kms')
        else:
            self.kms_client = kms_client
    
    def get_public_key_info(self, key_id):
        """Get public key information from AWS KMS."""
        key = self.kms_client.get_public_key(KeyId=key_id)
        metadata = self.kms_client.describe_key(KeyId=key_id)
        
        return {
            'public_key_der': key['PublicKey'],
            'key_spec': key['KeySpec'], 
            'creation_date': int(metadata['KeyMetadata']['CreationDate'].timestamp()),
            'arn': key['KeyId']
        }
    
    def get_key_tags(self, key_id):
        """Get key tags from AWS KMS."""
        try:
            tags_response = self.kms_client.list_resource_tags(KeyId=key_id)
            return {tag['TagKey']: tag['TagValue'] for tag in tags_response.get('Tags', [])}
        except Exception:
            return {}
    
    def sign_digest(self, key_id, digest, hash_length):
        """Sign a digest using AWS KMS."""
        signature = self.kms_client.sign(
            KeyId=key_id,
            Message=digest,
            MessageType='DIGEST',
            SigningAlgorithm=f'RSASSA_PKCS1_V1_5_SHA_{hash_length}'
        )
        return int.from_bytes(signature['Signature'], 'big')


class GoogleCloudKMSProvider(KMSProvider):
    """Google Cloud KMS provider implementation."""
    
    def __init__(self, kms_client=None):
        from google.cloud import kms
        
        if kms_client is None:
            self.kms_client = kms.KeyManagementServiceClient()
        else:
            self.kms_client = kms_client
    
    def get_public_key_info(self, key_id):
        """Get public key information from Google Cloud KMS."""
        from google.cloud import kms
        
        # Get public key
        public_key_response = self.kms_client.get_public_key(request={"name": key_id})
        
        # Get crypto key for metadata
        # Extract the crypto key name from the version name
        # Format: projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY/cryptoKeyVersions/VERSION
        crypto_key_name = '/'.join(key_id.split('/')[:-2])  # Remove cryptoKeyVersions/VERSION
        crypto_key_response = self.kms_client.get_crypto_key(request={"name": crypto_key_name})
        
        # Parse the public key DER
        public_key_der = public_key_response.pem.encode('utf-8')
        
        # Convert PEM to DER
        import base64
        pem_lines = public_key_der.decode('utf-8').split('\n')
        pem_content = ''.join([line for line in pem_lines if not line.startswith('-----')])
        public_key_der = base64.b64decode(pem_content)
        
        # Determine key spec from algorithm
        algorithm = public_key_response.algorithm
        if algorithm == kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256:
            key_spec = 'RSA_2048'
        elif algorithm == kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_3072_SHA256:
            key_spec = 'RSA_3072' 
        elif algorithm == kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256:
            key_spec = 'RSA_4096'
        else:
            key_spec = 'RSA_2048'  # Default
        
        return {
            'public_key_der': public_key_der,
            'key_spec': key_spec,
            'creation_date': int(crypto_key_response.create_time.timestamp()),
            'arn': key_id  # Use full resource name as ARN equivalent
        }
    
    def get_key_tags(self, key_id):
        """Get key labels from Google Cloud KMS."""
        try:
            # Extract the crypto key name from the version name
            crypto_key_name = '/'.join(key_id.split('/')[:-2])  # Remove cryptoKeyVersions/VERSION
            crypto_key_response = self.kms_client.get_crypto_key(request={"name": crypto_key_name})
            return dict(crypto_key_response.labels)
        except Exception:
            return {}
    
    def sign_digest(self, key_id, digest, hash_length):
        """Sign a digest using Google Cloud KMS."""
        from google.cloud import kms
        
        # Google Cloud KMS expects the full digest with DigestInfo structure for PKCS1 v1.5
        # We need to create the DigestInfo structure
        digest_info = self._create_digest_info(digest, hash_length)
        
        sign_response = self.kms_client.asymmetric_sign(
            request={
                "name": key_id,
                "digest": {"sha256": digest} if hash_length == 256 
                        else {"sha384": digest} if hash_length == 384 
                        else {"sha512": digest}
            }
        )
        
        return int.from_bytes(sign_response.signature, 'big')
    
    def _create_digest_info(self, digest, hash_length):
        """Create DigestInfo structure for PKCS1 v1.5 signing."""
        # DigestInfo structure according to RFC 3447
        sha256_prefix = bytes.fromhex('3031300d060960864801650304020105000420')
        sha384_prefix = bytes.fromhex('3041300d060960864801650304020205000430')  
        sha512_prefix = bytes.fromhex('3051300d060960864801650304020305000440')
        
        if hash_length == 256:
            return sha256_prefix + digest
        elif hash_length == 384:
            return sha384_prefix + digest
        elif hash_length == 512:
            return sha512_prefix + digest
        else:
            raise ValueError(f"Unsupported hash length: {hash_length}")


def get_kms_provider(key_id, kms_client=None):
    """
    Factory function to get the appropriate KMS provider.
    
    Args:
        key_id (str): Key identifier
        kms_client: Optional KMS client
        
    Returns:
        KMSProvider: Appropriate provider instance
    """
    provider_type = KMSProvider.detect_provider(key_id)
    
    if provider_type == 'aws':
        return AWSKMSProvider(kms_client)
    elif provider_type == 'gcp':
        return GoogleCloudKMSProvider(kms_client)
    else:
        raise ValueError(f"Unsupported KMS provider: {provider_type}")