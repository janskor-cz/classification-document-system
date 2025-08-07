#!/usr/bin/env python3
"""
Document Encryption with Ephemeral Public Keys
Working Package 3: Server-Side Ephemeral DID Integration

This module handles:
- Document encryption using user-generated ephemeral DIDs
- DID:key format parsing and validation
- Hybrid encryption (ECIES + AES-256-GCM)
- Temporary encrypted file management
- Integration with existing classification system
"""

import os
import json
import base64
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Any
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

import psycopg2
from psycopg2.extras import RealDictCursor

# Import configuration
from config import get_config

config = get_config()

class EphemeralDIDDocumentEncryption:
    """Handles document encryption using user-generated ephemeral DIDs"""
    
    def __init__(self):
        self.config = config
        self.temp_encryption_folder = Path("temp_encrypted")
        self.temp_encryption_folder.mkdir(exist_ok=True)
        
        print("🔒 EphemeralDIDDocumentEncryption initialized")
    
    def extract_public_key_from_did_key(self, did_key: str) -> Dict[str, Any]:
        """
        Extract public key from DID:key format
        
        Args:
            did_key: DID in format 'did:key:z6Mk...'
            
        Returns:
            Dict containing public key information
        """
        try:
            print(f"🔍 Extracting public key from DID: {did_key[:50]}...")
            
            # Validate DID:key format
            if not did_key.startswith('did:key:z'):
                raise ValueError("Invalid DID:key format")
            
            # Extract the encoded key part (remove 'did:key:z' prefix)
            encoded_key = did_key[9:]  # Remove 'did:key:z'
            
            # Decode from base58 (simplified implementation)
            # In production, use proper base58 decoding library
            key_bytes = self._base58_decode(encoded_key)
            
            # Parse multicodec prefix for key type
            if len(key_bytes) < 2:
                raise ValueError("Invalid key bytes length")
            
            # Check for P-256 multicodec prefix (0x1200)
            if key_bytes[0] == 0x12 and key_bytes[1] == 0x00:
                # P-256 public key
                public_key_bytes = key_bytes[2:]
                curve = ec.SECP256R1()
                key_type = "P-256"
            elif key_bytes[0] == 0x12 and key_bytes[1] == 0x01:
                # secp256k1 public key
                public_key_bytes = key_bytes[2:]
                curve = ec.SECP256K1()
                key_type = "secp256k1"
            else:
                raise ValueError(f"Unsupported key type: {key_bytes[0]:02x}{key_bytes[1]:02x}")
            
            # Create public key object
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key_bytes)
            
            # Convert to JWK format for consistency
            jwk = self._public_key_to_jwk(public_key, key_type)
            
            print(f"✅ Successfully extracted {key_type} public key from DID")
            
            return {
                "did_key": did_key,
                "key_type": key_type,
                "curve": curve.name,
                "public_key": public_key,
                "jwk": jwk,
                "raw_bytes": public_key_bytes
            }
            
        except Exception as error:
            print(f"❌ Failed to extract public key from DID: {error}")
            raise ValueError(f"Invalid DID:key format or unsupported key type: {error}")
    
    def _base58_decode(self, encoded: str) -> bytes:
        """
        Simple base58 decoding (placeholder - use proper library in production)
        
        Args:
            encoded: Base58 encoded string
            
        Returns:
            Decoded bytes
        """
        # This is a simplified implementation
        # In production, use a proper base58 library like 'base58'
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        
        # Convert to number
        num = 0
        for char in encoded:
            if char not in alphabet:
                raise ValueError(f"Invalid base58 character: {char}")
            num = num * 58 + alphabet.index(char)
        
        # Convert to bytes
        hex_str = hex(num)[2:]
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        
        return bytes.fromhex(hex_str)
    
    def _public_key_to_jwk(self, public_key: ec.EllipticCurvePublicKey, key_type: str) -> Dict[str, str]:
        """
        Convert public key to JWK format
        
        Args:
            public_key: EllipticCurvePublicKey object
            key_type: Key type (P-256, secp256k1)
            
        Returns:
            JWK representation
        """
        try:
            # Get the key numbers
            numbers = public_key.public_numbers()
            
            # Convert coordinates to bytes
            key_size = public_key.curve.key_size // 8
            x_bytes = numbers.x.to_bytes(key_size, byteorder='big')
            y_bytes = numbers.y.to_bytes(key_size, byteorder='big')
            
            # Create JWK
            if key_type == "P-256":
                crv = "P-256"
            elif key_type == "secp256k1":
                crv = "secp256k1"
            else:
                crv = key_type
            
            jwk = {
                "kty": "EC",
                "crv": crv,
                "x": base64.urlsafe_b64encode(x_bytes).decode('utf-8').rstrip('='),
                "y": base64.urlsafe_b64encode(y_bytes).decode('utf-8').rstrip('=')
            }
            
            return jwk
            
        except Exception as error:
            print(f"❌ Failed to convert public key to JWK: {error}")
            raise
    
    def encrypt_document_with_ephemeral_public_key(self, 
                                                  document_data: bytes,
                                                  ephemeral_public_key_info: Dict[str, Any],
                                                  session_id: int) -> Dict[str, Any]:
        """
        Encrypt document using ephemeral public key with hybrid encryption
        
        Args:
            document_data: Document content as bytes
            ephemeral_public_key_info: Public key info from extract_public_key_from_did_key
            session_id: Database session ID for tracking
            
        Returns:
            Dict containing encrypted document information
        """
        try:
            print(f"🔒 Encrypting document with ephemeral key for session {session_id}...")
            
            # Generate random symmetric key for AES-256-GCM
            symmetric_key = secrets.token_bytes(32)  # 256 bits
            iv = secrets.token_bytes(12)  # 96 bits for GCM
            
            # Encrypt document with AES-256-GCM
            cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            
            encrypted_document = encryptor.update(document_data) + encryptor.finalize()
            auth_tag = encryptor.tag
            
            # Encrypt symmetric key with ephemeral public key using ECIES
            public_key = ephemeral_public_key_info["public_key"]
            encrypted_key = self._encrypt_key_with_ecies(symmetric_key, public_key)
            
            # Create temporary encrypted file
            temp_filename = f"session_{session_id}_{secrets.token_hex(8)}.enc"
            temp_filepath = self.temp_encryption_folder / temp_filename
            
            # Store encrypted data structure
            encrypted_data = {
                "encrypted_document": base64.b64encode(encrypted_document).decode('utf-8'),
                "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8'),
                "auth_tag": base64.b64encode(auth_tag).decode('utf-8'),
                "algorithm": "ECIES-P256-AES256GCM",
                "ephemeral_did": ephemeral_public_key_info["did_key"],
                "session_id": session_id,
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(hours=2)).isoformat()  # 2 hour expiry
            }
            
            # Write encrypted data to temporary file
            with open(temp_filepath, 'w') as f:
                json.dump(encrypted_data, f)
            
            print(f"✅ Document encrypted successfully, stored in {temp_filename}")
            
            return {
                "encrypted_file_path": str(temp_filepath),
                "temp_filename": temp_filename,
                "encryption_algorithm": "ECIES-P256-AES256GCM",
                "encrypted_size": len(encrypted_document),
                "original_size": len(document_data),
                "session_id": session_id,
                "ephemeral_did": ephemeral_public_key_info["did_key"],
                "created_at": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(hours=2)
            }
            
        except Exception as error:
            print(f"❌ Document encryption failed: {error}")
            raise RuntimeError(f"Failed to encrypt document: {error}")
    
    def _encrypt_key_with_ecies(self, symmetric_key: bytes, public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Encrypt symmetric key using ECIES (Elliptic Curve Integrated Encryption Scheme)
        
        Args:
            symmetric_key: AES key to encrypt
            public_key: Ephemeral public key
            
        Returns:
            Encrypted key bytes
        """
        try:
            # Generate ephemeral key pair for ECIES
            ephemeral_private_key = ec.generate_private_key(public_key.curve)
            ephemeral_public_key = ephemeral_private_key.public_key()
            
            # Perform ECDH
            shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
            
            # Derive encryption key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256 key length
                salt=None,
                info=b'ECIES encryption',
            ).derive(shared_key)
            
            # Encrypt symmetric key with derived key
            iv = secrets.token_bytes(12)
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            
            encrypted_key = encryptor.update(symmetric_key) + encryptor.finalize()
            auth_tag = encryptor.tag
            
            # Serialize ephemeral public key
            ephemeral_public_bytes = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            # Combine all components
            result = ephemeral_public_bytes + iv + auth_tag + encrypted_key
            
            return result
            
        except Exception as error:
            print(f"❌ ECIES encryption failed: {error}")
            raise
    
    def prepare_ephemeral_encrypted_response(self, 
                                           encrypted_data: Dict[str, Any],
                                           session_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare response for client-side decryption
        
        Args:
            encrypted_data: Result from encrypt_document_with_ephemeral_public_key
            session_info: Session information from database
            
        Returns:
            Response for client
        """
        return {
            "success": True,
            "encryptedDocument": {
                "data": self._read_encrypted_file(encrypted_data["encrypted_file_path"]),
                "algorithm": encrypted_data["encryption_algorithm"],
                "encryptedSize": encrypted_data["encrypted_size"],
                "originalSize": encrypted_data["original_size"]
            },
            "sessionInfo": {
                "sessionToken": session_info["session_token"],
                "ephemeralDID": encrypted_data["ephemeral_did"],
                "expiresAt": encrypted_data["expires_at"].isoformat(),
                "sessionId": encrypted_data["session_id"]
            },
            "instructions": "Use your ephemeral private key to decrypt this document in your browser",
            "security": {
                "perfectForwardSecrecy": True,
                "clientSideDecryption": True,
                "serverKeyExposure": False
            }
        }
    
    def _read_encrypted_file(self, file_path: str) -> Dict[str, Any]:
        """
        Read encrypted file data
        
        Args:
            file_path: Path to encrypted file
            
        Returns:
            Encrypted data structure
        """
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as error:
            print(f"❌ Failed to read encrypted file: {error}")
            raise
    
    def validate_ephemeral_did_format(self, did: str) -> bool:
        """
        Validate DID:key format for ephemeral access
        
        Args:
            did: DID string to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Basic format check
            if not isinstance(did, str) or not did.startswith('did:key:z'):
                return False
            
            # Length check (reasonable bounds)
            if len(did) < 20 or len(did) > 200:
                return False
            
            # Character validation (base58)
            encoded_part = did[9:]  # Remove 'did:key:z'
            alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            
            for char in encoded_part:
                if char not in alphabet:
                    return False
            
            # Try to extract public key (will raise exception if invalid)
            self.extract_public_key_from_did_key(did)
            
            return True
            
        except Exception as error:
            print(f"⚠️  DID validation failed: {error}")
            return False
    
    def cleanup_ephemeral_encrypted_files(self, session_id: int) -> bool:
        """
        Clean up temporary encrypted files after session expiry
        
        Args:
            session_id: Session ID to clean up
            
        Returns:
            True if successful, False otherwise
        """
        try:
            print(f"🧹 Cleaning up encrypted files for session {session_id}...")
            
            cleaned_count = 0
            
            # Find files matching session pattern
            pattern = f"session_{session_id}_*.enc"
            for file_path in self.temp_encryption_folder.glob(pattern):
                try:
                    file_path.unlink()  # Delete file
                    cleaned_count += 1
                    print(f"🗑️  Deleted: {file_path.name}")
                except Exception as file_error:
                    print(f"⚠️  Failed to delete {file_path.name}: {file_error}")
            
            print(f"✅ Cleaned up {cleaned_count} encrypted files for session {session_id}")
            return True
            
        except Exception as error:
            print(f"❌ Cleanup failed for session {session_id}: {error}")
            return False
    
    def cleanup_expired_files(self, max_age_hours: int = 2) -> int:
        """
        Clean up all expired temporary encrypted files
        
        Args:
            max_age_hours: Maximum age in hours before cleanup
            
        Returns:
            Number of files cleaned up
        """
        try:
            print(f"🧹 Cleaning up files older than {max_age_hours} hours...")
            
            cleaned_count = 0
            cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
            
            for file_path in self.temp_encryption_folder.glob("session_*.enc"):
                try:
                    # Check file modification time
                    file_mtime = datetime.utcfromtimestamp(file_path.stat().st_mtime)
                    
                    if file_mtime < cutoff_time:
                        file_path.unlink()
                        cleaned_count += 1
                        print(f"🗑️  Deleted expired file: {file_path.name}")
                        
                except Exception as file_error:
                    print(f"⚠️  Failed to process {file_path.name}: {file_error}")
            
            print(f"✅ Cleaned up {cleaned_count} expired encrypted files")
            return cleaned_count
            
        except Exception as error:
            print(f"❌ Expired file cleanup failed: {error}")
            return 0
    
    def get_session_encrypted_file(self, session_id: int) -> Optional[str]:
        """
        Get encrypted file path for session
        
        Args:
            session_id: Session ID
            
        Returns:
            File path if found, None otherwise
        """
        try:
            pattern = f"session_{session_id}_*.enc"
            matching_files = list(self.temp_encryption_folder.glob(pattern))
            
            if matching_files:
                return str(matching_files[0])
            else:
                return None
                
        except Exception as error:
            print(f"❌ Failed to find encrypted file for session {session_id}: {error}")
            return None

# Global instance
ephemeral_encryption = EphemeralDIDDocumentEncryption()

def validate_did_key_format(did_key: str) -> bool:
    """
    Convenience function to validate DID:key format
    
    Args:
        did_key: DID key to validate
        
    Returns:
        True if valid, False otherwise
    """
    return ephemeral_encryption.validate_ephemeral_did_format(did_key)

def encrypt_document_for_ephemeral_session(document_data: bytes, 
                                         ephemeral_did: str, 
                                         session_id: int) -> Dict[str, Any]:
    """
    Convenience function to encrypt document for ephemeral session
    
    Args:
        document_data: Document content
        ephemeral_did: User's ephemeral DID
        session_id: Session ID
        
    Returns:
        Encryption result
    """
    try:
        # Extract public key from DID
        public_key_info = ephemeral_encryption.extract_public_key_from_did_key(ephemeral_did)
        
        # Encrypt document
        return ephemeral_encryption.encrypt_document_with_ephemeral_public_key(
            document_data, public_key_info, session_id
        )
    except Exception as error:
        print(f"❌ Document encryption failed: {error}")
        raise

def cleanup_session_files(session_id: int) -> bool:
    """
    Convenience function to cleanup session files
    
    Args:
        session_id: Session ID to cleanup
        
    Returns:
        True if successful
    """
    return ephemeral_encryption.cleanup_ephemeral_encrypted_files(session_id)

# Initialize cleanup on import
print("🔒 Document encryption system initialized")

# Automatic cleanup of expired files (can be called periodically)
def periodic_cleanup():
    """Periodic cleanup of expired encrypted files"""
    return ephemeral_encryption.cleanup_expired_files()

if __name__ == "__main__":
    # Test the encryption system
    print("🧪 Testing ephemeral DID document encryption...")
    
    # Test DID validation
    test_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    print(f"✅ DID validation test: {validate_did_key_format(test_did)}")
    
    # Test cleanup
    cleaned = periodic_cleanup()
    print(f"✅ Cleanup test: {cleaned} files cleaned")
    
    print("🎉 Ephemeral DID document encryption system ready!")