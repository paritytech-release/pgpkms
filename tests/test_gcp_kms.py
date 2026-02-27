"""
Unit tests for KmsPgpKey functionality with Google Cloud KMS provider.
"""

import unittest
from unittest.mock import Mock, patch
import tempfile
import os
import sys
from datetime import datetime
from io import BytesIO, StringIO, BufferedReader

# Add the parent directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pgpkms import KmsPgpKey


class TestGCPKmsPgpKey(unittest.TestCase):
    """Unit tests for KmsPgpKey functionality with Google Cloud KMS provider."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_creation_date = datetime(2023, 1, 1, 0, 0, 0)  # 2023-01-01 00:00:00 UTC
        self.mock_creation_timestamp = 1672531200  # corresponding timestamp
        
        # Use real RSA 2048-bit public key DER bytes (from a test key)
        # This is a real DER-encoded 2048-bit RSA public key
        self.mock_public_key_der = bytes.fromhex(
            "30820122300d06092a864886f70d01010105000382010f003082010a0282010100"
            "c096d817dea2db0c412c4cf706729f0e1f2e016aa12a85259727f4fd15bd65f2332"
            "fd074b45d8135f3db19f45519b1321bc1a32f2aaf27b4dc0cc684ecc97c43319618"
            "f06a08fedd2f553750070f659982507cb9e643db78b65f4bee2dc980a1509bc532"
            "15e4f99f74ca6606782bb439151f2b38f8bfd47d950b04e8a94bd1a2d48ef122e8"
            "917b17b47c9369d8712eed36f6cbe10f2830add07cbd86e4f643250937178b0bbc"
            "bf14ea636b43d2b827423838bf3d6a709c93d2b17c6d2f0fd9591d244e58d8abd1"
            "e42ded329ab5849d2f1775b9a39a3c2bb846f5c5fd2fb8c7c61597c5aba1bc489"
            "b77477139a09d04daa409eef17d70edded2cd6227b1f541020203010001"
        )
        
        self.mock_signature = bytes(range(256))  # Mock signature

    def create_gcp_key_with_mocks(self, key_id='projects/test/locations/us/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1',
                                  name='Test User', email='test@example.com'):
        """Create a KmsPgpKey with GCP mocks."""
        import base64
        
        with patch('google.cloud.kms.KeyManagementServiceClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            # Mock GCP KMS responses
            mock_public_key = Mock()
            pem_body = base64.b64encode(self.mock_public_key_der).decode('ascii')
            mock_public_key.pem = f"""-----BEGIN PUBLIC KEY-----
{pem_body}
-----END PUBLIC KEY-----"""
            mock_client.get_public_key.return_value = mock_public_key
            
            mock_crypto_key = Mock()
            labels = {}
            if name:
                labels['pgp-name'] = name
            if email:
                labels['pgp-email'] = email
            mock_crypto_key.labels = labels
            
            mock_crypto_key.create_time.timestamp.return_value = self.mock_creation_timestamp
            mock_client.get_crypto_key.return_value = mock_crypto_key
            
            mock_sign_response = Mock()
            mock_sign_response.signature = self.mock_signature
            mock_client.asymmetric_sign.return_value = mock_sign_response
            
            return KmsPgpKey(key_id), mock_client

    def test_gcp_key_initialization_with_labels(self):
        """Test GCP key initialization with pgp-name/pgp-email labels."""
        key, _ = self.create_gcp_key_with_mocks(name='Jane Doe', email='jane-at-example-dot-com')

        self.assertEqual(key.user_id, 'Jane Doe <jane@example.com>')
        self.assertEqual(key.bits, 2048)
        self.assertEqual(key.creation_date, self.mock_creation_timestamp)

    def test_gcp_key_initialization_name_only(self):
        """Test GCP key initialization with only name."""
        key, _ = self.create_gcp_key_with_mocks(name='Test User', email=None)
        self.assertEqual(key.user_id, 'Test User')

    def test_gcp_key_initialization_email_only(self):
        """Test GCP key initialization with only email."""
        key, _ = self.create_gcp_key_with_mocks(name=None, email='test-at-example-dot-com')
        self.assertEqual(key.user_id, 'test@example.com')

    def test_gcp_key_initialization_no_labels(self):
        """Test GCP key initialization with no labels (fallback user ID)."""
        key, _ = self.create_gcp_key_with_mocks(name=None, email=None)
        self.assertIn('PgpKms-Wrapper', key.user_id)

    def test_gcp_provider_calls(self):
        """Test that GCP provider methods are called correctly."""
        key, mock_client = self.create_gcp_key_with_mocks()
        
        # Test basic functionality
        with patch('time.time', return_value=1672574400):
            pgp_key = key.to_pgp()
            signature = key.sign("test data")
        
        # Verify GCP client methods were called
        mock_client.get_public_key.assert_called()
        mock_client.get_crypto_key.assert_called()
        mock_client.asymmetric_sign.assert_called()

    def test_gcp_to_pgp_armoured(self):
        """Test GCP PGP public key export (armoured)."""
        key, mock_client = self.create_gcp_key_with_mocks()
        
        with patch('time.time', return_value=1672574400):
            pgp_key = key.to_pgp(armoured=True)
        
        self.assertIsInstance(pgp_key, bytes)
        pgp_str = pgp_key.decode('utf-8')
        self.assertIn('-----BEGIN PGP PUBLIC KEY BLOCK-----', pgp_str)
        self.assertIn('-----END PGP PUBLIC KEY BLOCK-----', pgp_str)

    def test_gcp_to_pgp_binary(self):
        """Test GCP PGP public key export (binary)."""
        key, mock_client = self.create_gcp_key_with_mocks()
        
        with patch('time.time', return_value=1672574400):
            pgp_key = key.to_pgp(armoured=False)
        
        self.assertIsInstance(pgp_key, bytes)
        # Binary should not contain PGP headers
        self.assertNotIn(b'-----BEGIN PGP PUBLIC KEY BLOCK-----', pgp_key)

    def test_gcp_sign_string_input(self):
        """Test GCP signing string input."""
        key, mock_client = self.create_gcp_key_with_mocks()
        
        with patch('time.time', return_value=1672574400):
            signature = key.sign("Hello, World!")
        
        self.assertIsInstance(signature, bytes)
        sig_str = signature.decode('utf-8')
        self.assertIn('-----BEGIN PGP SIGNATURE-----', sig_str)
        self.assertIn('-----END PGP SIGNATURE-----', sig_str)

    def test_gcp_sign_bytes_input(self):
        """Test GCP signing bytes input."""
        key, mock_client = self.create_gcp_key_with_mocks()
        
        with patch('time.time', return_value=1672574400):
            signature = key.sign(b"Hello, World!")
        
        self.assertIsInstance(signature, bytes)
        sig_str = signature.decode('utf-8')
        self.assertIn('-----BEGIN PGP SIGNATURE-----', sig_str)

    def test_gcp_message_string_input(self):
        """Test GCP creating signed message from string."""
        key, mock_client = self.create_gcp_key_with_mocks()
        
        test_message = "Hello, World!\nThis is a test message."
        
        with patch('time.time', return_value=1672574400):
            signed_message = key.message(test_message)
        
        self.assertIsInstance(signed_message, str)
        self.assertIn('-----BEGIN PGP SIGNED MESSAGE-----', signed_message)
        self.assertIn('Hash: SHA256', signed_message)
        self.assertIn('Hello, World!', signed_message)
        self.assertIn('-----BEGIN PGP SIGNATURE-----', signed_message)


if __name__ == '__main__':
    unittest.main()