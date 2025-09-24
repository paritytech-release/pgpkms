"""
Generic unit tests for KmsPgpKey functionality that work with any provider.
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


class TestGenericKmsPgpKey(unittest.TestCase):
    """Generic unit tests for KmsPgpKey functionality."""

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

    def create_aws_key_with_mocks(self, key_id='arn:aws:kms:us-east-1:123456789012:key/test-key', 
                                  name='Test User', email='test@example.com'):
        """Create a KmsPgpKey with AWS mocks."""
        with patch('botocore.session.get_session') as mock_get_session:
            mock_session = Mock()
            mock_client = Mock()
            
            # Setup session and client
            mock_get_session.return_value = mock_session
            mock_session.create_client.return_value = mock_client
            
            # Mock AWS KMS responses
            mock_client.get_public_key.return_value = {
                'KeyId': key_id,
                'KeySpec': 'RSA_2048',
                'PublicKey': self.mock_public_key_der
            }
            
            mock_client.describe_key.return_value = {
                'KeyMetadata': {
                    'KeyId': key_id,
                    'CreationDate': self.mock_creation_date
                }
            }
            
            if name and email:
                tags = [
                    {'TagKey': 'PGPName', 'TagValue': name},
                    {'TagKey': 'PGPEmail', 'TagValue': email}
                ]
            elif name:
                tags = [{'TagKey': 'PGPName', 'TagValue': name}]
            elif email:
                tags = [{'TagKey': 'PGPEmail', 'TagValue': email}]
            else:
                tags = []
                
            mock_client.list_resource_tags.return_value = {'Tags': tags}
            
            mock_client.sign.return_value = {'Signature': self.mock_signature}
            
            return KmsPgpKey(key_id), mock_client

    def test_to_pgp_different_hash_algorithms(self):
        """Test PGP key export with different hash algorithms."""
        key, mock_client = self.create_aws_key_with_mocks()
        
        for hash_alg in ['sha256', 'sha384', 'sha512']:
            with self.subTest(hash_algorithm=hash_alg):
                with patch('time.time', return_value=1672574400):
                    pgp_key = key.to_pgp(hash=hash_alg)
                
                self.assertIsInstance(pgp_key, bytes)
                self.assertGreater(len(pgp_key), 0)

    def test_to_pgp_invalid_hash(self):
        """Test PGP key export with invalid hash algorithm."""
        key, _ = self.create_aws_key_with_mocks()
        
        with self.assertRaises(AssertionError):
            key.to_pgp(hash='invalid')

    def test_sign_file_input(self):
        """Test signing file-like input."""
        key, mock_client = self.create_aws_key_with_mocks()
        # Wrap BytesIO in BufferedReader to match accepted types
        file_content = BufferedReader(BytesIO(b"Hello from file!"))
        with patch('time.time', return_value=1672574400):
            signature = key.sign(file_content)
        self.assertIsInstance(signature, bytes)
        sig_str = signature.decode('utf-8')
        self.assertIn('-----BEGIN PGP SIGNATURE-----', sig_str)

    def test_sign_invalid_input(self):
        """Test signing with invalid input type."""
        key, _ = self.create_aws_key_with_mocks()
        
        with self.assertRaises(AssertionError):
            key.sign(123)  # Invalid type

    def test_sign_different_hash_algorithms(self):
        """Test signing with different hash algorithms."""
        key, mock_client = self.create_aws_key_with_mocks()
        
        for hash_alg in ['sha256', 'sha384', 'sha512']:
            with self.subTest(hash_algorithm=hash_alg):
                with patch('time.time', return_value=1672574400):
                    signature = key.sign("test data", hash=hash_alg)
                
                self.assertIsInstance(signature, bytes)

    def test_sign_binary_vs_armoured(self):
        """Test signing with armoured vs binary output."""
        key, mock_client = self.create_aws_key_with_mocks()
        
        with patch('time.time', return_value=1672574400):
            sig_armoured = key.sign("test", armoured=True)
            sig_binary = key.sign("test", armoured=False)
        
        # Armoured should be longer and contain headers
        self.assertGreater(len(sig_armoured), len(sig_binary))
        self.assertIn(b'-----BEGIN PGP SIGNATURE-----', sig_armoured)
        self.assertNotIn(b'-----BEGIN PGP SIGNATURE-----', sig_binary)

    def test_message_bytes_input(self):
        """Test creating signed message from bytes."""
        key, mock_client = self.create_aws_key_with_mocks()
        
        test_message = b"Hello, World!\nThis is a test message."
        
        with patch('time.time', return_value=1672574400):
            signed_message = key.message(test_message)
        
        self.assertIsInstance(signed_message, str)
        self.assertIn('Hello, World!', signed_message)

    def test_message_with_output_buffer(self):
        """Test creating signed message with output buffer."""
        key, mock_client = self.create_aws_key_with_mocks()
        
        test_message = "Hello, World!"
        output_buffer = BytesIO()
        
        with patch('time.time', return_value=1672574400):
            result = key.message(test_message, output=output_buffer)
        
        # Should return None when output buffer is provided
        self.assertIsNone(result)
        
        # Check buffer content
        buffer_content = output_buffer.getvalue().decode('utf-8')
        self.assertIn('-----BEGIN PGP SIGNED MESSAGE-----', buffer_content)
        self.assertIn('Hello, World!', buffer_content)

    def test_message_dash_escaping(self):
        """Test that lines starting with dashes are properly escaped."""
        key, mock_client = self.create_aws_key_with_mocks()
        
        test_message = "Regular line\n- Line with dash\n-- Double dash"
        
        with patch('time.time', return_value=1672574400):
            signed_message = key.message(test_message)
        
        # Lines starting with dashes should be escaped with '- '
        lines = signed_message.split('\n')
        dash_lines = [line for line in lines if line.startswith('- -')]
        self.assertTrue(len(dash_lines) > 0, "Dash lines should be escaped")

    def test_key_expiration_parameter(self):
        """Test PGP key creation with custom expiration."""
        key, mock_client = self.create_aws_key_with_mocks()
        
        # Test with custom expiration
        with patch('time.time', return_value=1672574400):
            pgp_key_30_days = key.to_pgp(expiration=30)
            pgp_key_365_days = key.to_pgp(expiration=365)
        
        self.assertIsInstance(pgp_key_30_days, bytes)
        self.assertIsInstance(pgp_key_365_days, bytes)
        
        # Keys with different expiration should be different
        self.assertNotEqual(pgp_key_30_days, pgp_key_365_days)

    def test_key_expiration_invalid_values(self):
        """Test PGP key creation with invalid expiration values."""
        key, _ = self.create_aws_key_with_mocks()
        
        # Test with invalid expiration (less than 1 day)
        with self.assertRaises(ValueError):
            key.to_pgp(expiration=0)
        
        with self.assertRaises(ValueError):
            key.to_pgp(expiration=-1)

    def test_utility_functions(self):
        """Test the utility functions used in PGP operations."""
        key, _ = self.create_aws_key_with_mocks()
        
        # Test that internal properties work
        self.assertIsNotNone(key._KmsPgpKey__pgp_key)
        self.assertIsNotNone(key._KmsPgpKey__pgp_fingerprint)
        self.assertIsNotNone(key._KmsPgpKey__pgp_key_id)
        
        # Test fingerprint is correct length (20 bytes for SHA1)
        self.assertEqual(len(key._KmsPgpKey__pgp_fingerprint), 20)
        
        # Test key ID is correct length (8 bytes)
        self.assertEqual(len(key._KmsPgpKey__pgp_key_id), 8)


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions in the pgpkms module."""
    
    def test_packet_function(self):
        """Test the __packet utility function."""
        from pgpkms.pgpkms import _KmsPgpKey__packet
        
        # Test with small payload
        payload = b"test"
        packet = _KmsPgpKey__packet(0x06, payload)
        
        self.assertIsInstance(packet, bytes)
        self.assertGreater(len(packet), len(payload))
        
    def test_subpacket_function(self):
        """Test the __subpacket utility function."""
        from pgpkms.pgpkms import _KmsPgpKey__subpacket
        
        # Test with small subpacket
        subpacket = _KmsPgpKey__subpacket(b'\x02', b'\x12\x34\x56\x78')
        
        self.assertIsInstance(subpacket, bytes)
        self.assertEqual(len(subpacket), 6)  # 1 byte length + 1 byte type + 4 bytes value
        
    def test_mpi_function(self):
        """Test the __mpi utility function."""
        from pgpkms.pgpkms import _KmsPgpKey__mpi
        
        # Test with a number
        number = 65537  # Common RSA exponent
        mpi = _KmsPgpKey__mpi(number)
        
        self.assertIsInstance(mpi, bytes)
        self.assertGreaterEqual(len(mpi), 4)  # At least 2 bytes length + some data


if __name__ == '__main__':
    unittest.main()