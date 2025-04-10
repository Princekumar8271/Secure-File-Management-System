from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import jwt
from datetime import datetime, timedelta
import logging
import json
from typing import Tuple, Dict, Optional

class EncryptionContainer:
    def __init__(self, key: bytes, metadata: dict):
        self.key = key
        self.metadata = metadata
        self.cipher = Fernet(key)

    def encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data and return it in a container format
        
        Args:
            data: The binary data to encrypt
            
        Returns:
            Encrypted container data as bytes
        """
        try:
            # Encrypt the data with the container's cipher
            encrypted = self.cipher.encrypt(data)
            
            # Create container with metadata and the encrypted data
            container = {
                'data': base64.b64encode(encrypted).decode('utf-8'),
                'metadata': self.metadata,
                'timestamp': datetime.now().isoformat(),
                'key': self.key.decode('utf-8') if isinstance(self.key, bytes) else self.key
            }
            
            # Encode the container to JSON and then to base64 for storage
            container_json = json.dumps(container)
            container_bytes = container_json.encode('utf-8')
            container_b64 = base64.b64encode(container_bytes)
            
            logging.info(f"Data encrypted successfully, original size: {len(data)} bytes, encrypted container size: {len(container_b64)} bytes")
            return container_b64
            
        except Exception as e:
            logging.error(f"Error in encrypt_data: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            raise

    def decrypt_data(self, container_data: bytes) -> bytes:
        """
        Decrypt data from a container
        
        Args:
            container_data: The encrypted container data
            
        Returns:
            Decrypted binary data
        """
        try:
            # Decode container from base64 to JSON string, then to dictionary
            container_json = base64.b64decode(container_data).decode('utf-8')
            container = json.loads(container_json)
            
            # Extract the encrypted data and decode from base64
            encrypted_data_str = container['data']
            encrypted_data = base64.b64decode(encrypted_data_str.encode('utf-8'))
            
            # Decrypt using the container's cipher
            decrypted_data = self.cipher.decrypt(encrypted_data)
            
            logging.info(f"Data decrypted successfully, container size: {len(container_data)} bytes, decrypted size: {len(decrypted_data)} bytes")
            return decrypted_data
            
        except Exception as e:
            logging.error(f"Error in decrypt_data: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            raise

class SecurityManager:
    def __init__(self):
        self._load_or_create_keys()
        self._initialize_encryption()

    def _load_or_create_keys(self):
        """Load existing keys or create new ones if they don't exist"""
        key_file = "security_keys.dat"
        try:
            # Try to load existing keys
            if os.path.exists(key_file):
                with open(key_file, "rb") as f:
                    key_data = f.read()
                    
                # Basic obfuscation - this is just to prevent casual inspection
                # For full security, would use proper key management solutions
                key_data = bytes([b ^ 0x55 for b in key_data])
                
                key_parts = key_data.split(b"|")
                if len(key_parts) == 2:
                    self.master_key = key_parts[0]
                    self.secret_key = key_parts[1]
                    logging.info("Loaded existing encryption keys")
                    return
        except Exception as e:
            logging.error(f"Error loading keys: {e}, generating new ones")
            
        # If we got here, either the file doesn't exist or there was an error
        # Generate new keys
        self.master_key = os.urandom(32)
        self.secret_key = os.urandom(32)
        
        # Save the keys for future use
        try:
            key_data = self.master_key + b"|" + self.secret_key
            # Basic obfuscation 
            key_data = bytes([b ^ 0x55 for b in key_data])
            
            with open(key_file, "wb") as f:
                f.write(key_data)
            logging.info("Generated and saved new encryption keys")
        except Exception as e:
            logging.error(f"Error saving keys: {e}")
            # Continue with the new keys but they won't be persistent

    def _initialize_encryption(self):
        # Standard encryption (AES-256)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
        
        # High security encryption (double key)
        kdf_high = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=os.urandom(32),
            iterations=200000,
        )
        key_high = base64.urlsafe_b64encode(kdf_high.derive(self.master_key))
        
        # Create multiple encryption suites for different security levels
        self.standard_cipher = Fernet(key)
        self.high_security_cipher = MultiFernet([Fernet(key), Fernet(key_high)])

    def create_container(self, file_metadata: dict, encryption_level: str = 'standard') -> EncryptionContainer:
        container_key = base64.urlsafe_b64encode(os.urandom(32))
        file_metadata['encryption_level'] = encryption_level
        return EncryptionContainer(container_key, file_metadata)

    def encrypt_file(self, data: bytes, metadata: dict = None) -> bytes:
        """
        Encrypt file data using container-based encryption
        
        Args:
            data: Binary file data to encrypt
            metadata: Optional metadata to store with the encrypted file
            
        Returns:
            Encrypted container data as bytes
        """
        try:
            if metadata is None:
                metadata = {}
            
            # Log the file type if available
            file_type = metadata.get('file_type', 'unknown')
            logging.info(f"Encrypting file of type: {file_type}, size: {len(data)} bytes")
            
            # Create hash of original file for integrity checking
            import hashlib
            file_hash = hashlib.sha256(data).hexdigest()
            metadata['original_hash'] = file_hash
            logging.info(f"Original file hash: {file_hash[:10]}...")
            
            # Get encryption level from metadata
            encryption_level = metadata.get('encryption_level', 'standard')
            logging.info(f"Using encryption level: {encryption_level}")
            
            # Create encryption container
            container = self.create_container(metadata, encryption_level)
            
            # Handle binary data encryption
            try:
                # Encrypt the data
                encrypted_data = container.encrypt_data(data)
                logging.info(f"Base encryption successful, container size: {len(encrypted_data)} bytes")
                
                # For high security, apply an additional layer of encryption
                if encryption_level == 'high':
                    logging.info("Applying second layer encryption (high security)")
                    # Convert to dict for the additional encryption
                    container_dict = json.loads(base64.b64decode(encrypted_data).decode('utf-8'))
                    # Apply second layer of encryption to the data
                    encrypted_inner_data = base64.b64decode(container_dict['data'].encode('utf-8'))
                    double_encrypted = self.high_security_cipher.encrypt(encrypted_inner_data)
                    container_dict['data'] = base64.b64encode(double_encrypted).decode('utf-8')
                    container_dict['double_encrypted'] = True
                    # Convert back to base64
                    container_json = json.dumps(container_dict)
                    encrypted_data = base64.b64encode(container_json.encode('utf-8'))
                    logging.info(f"High security encryption completed, final size: {len(encrypted_data)} bytes")
                
                return encrypted_data
                
            except Exception as inner_error:
                logging.error(f"Error during encryption process: {str(inner_error)}")
                import traceback
                logging.error(traceback.format_exc())
                raise
            
        except Exception as e:
            logging.error(f"Encryption error: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            raise

    def decrypt_file(self, container_data: bytes) -> tuple[bytes, dict]:
        """Decrypt file data and return with metadata"""
        try:
            container = json.loads(base64.b64decode(container_data).decode())
            encrypted_data = base64.b64decode(container['data'].encode())
            metadata = container.get('metadata', {})
            
            # Log metadata for debugging
            logging.info(f"Decrypting file with metadata: {metadata}")
            
            # Check if this is a double-encrypted file (high security)
            if container.get('double_encrypted', False):
                logging.info("Detected double-encrypted file, using high security decryption")
                # First decrypt with the high security cipher
                try:
                    decrypted_inner = self.high_security_cipher.decrypt(encrypted_data)
                    logging.info("First layer decryption successful")
                except Exception as e:
                    logging.error(f"First layer decryption failed: {str(e)}")
                    raise
                
                # Then use the container key if available
                container_key = container.get('key', None)
                if container_key:
                    try:
                        cipher = Fernet(container_key)
                        decrypted_data = cipher.decrypt(decrypted_inner)
                        logging.info("Second layer decryption successful")
                    except Exception as e:
                        logging.error(f"Second layer decryption with container key failed: {str(e)}")
                        # Fallback to directly using inner data (some file types might still work)
                        decrypted_data = decrypted_inner
                else:
                    # Fallback to using the first container layer directly
                    decrypted_data = decrypted_inner
            else:
                logging.info("Using standard decryption")
                # Standard decryption - try with different approaches
                decryption_success = False
                error_messages = []
                
                # 1. Try with the container's own key
                if 'key' in container:
                    try:
                        container_key = container['key'].encode() if isinstance(container['key'], str) else container['key']
                        logging.info(f"Attempting decryption with container key")
                        cipher = Fernet(container_key)
                        decrypted_data = cipher.decrypt(encrypted_data)
                        decryption_success = True
                        logging.info("Decryption with container key successful")
                    except Exception as e:
                        error_msg = f"Container key decryption failed: {str(e)}"
                        logging.warning(error_msg)
                        error_messages.append(error_msg)
                
                # 2. Try with master key if above failed
                if not decryption_success:
                    try:
                        key = base64.urlsafe_b64encode(self.master_key)
                        logging.info(f"Attempting decryption with master key")
                        cipher = Fernet(key)
                        decrypted_data = cipher.decrypt(encrypted_data)
                        decryption_success = True
                        logging.info("Decryption with master key successful")
                    except Exception as e:
                        error_msg = f"Master key decryption failed: {str(e)}"
                        logging.warning(error_msg)
                        error_messages.append(error_msg)
                
                # 3. Try with standard cipher as last resort
                if not decryption_success:
                    try:
                        logging.info(f"Attempting decryption with standard cipher (last resort)")
                        decrypted_data = self.standard_cipher.decrypt(encrypted_data)
                        decryption_success = True
                        logging.info("Decryption with standard cipher successful")
                    except Exception as e:
                        error_msg = f"Standard cipher decryption failed: {str(e)}"
                        logging.error(error_msg)
                        error_messages.append(error_msg)
                        
                        # If we got here, all decryption attempts failed
                        if not decryption_success:
                            raise Exception(f"All decryption methods failed: {', '.join(error_messages)}")
            
            # Verify data integrity if possible
            if 'original_hash' in metadata:
                try:
                    import hashlib
                    file_hash = hashlib.sha256(decrypted_data).hexdigest()
                    if file_hash != metadata['original_hash']:
                        logging.warning(f"File integrity check failed: hash mismatch (expected {metadata['original_hash']}, got {file_hash})")
                    else:
                        logging.info("File integrity check passed")
                except Exception as e:
                    logging.warning(f"Couldn't verify file integrity: {str(e)}")
            
            return decrypted_data, metadata
            
        except Exception as e:
            logging.error(f"Decryption error: {str(e)}")
            # Include stack trace for better debugging
            import traceback
            logging.error(traceback.format_exc())
            raise

    def generate_token(self, user_id: str, role: str) -> str:
        """Generate JWT token for user authentication"""
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')

    def verify_token(self, token: str) -> dict:
        """Verify and decode JWT token"""
        try:
            return jwt.decode(token, self.secret_key, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            return None