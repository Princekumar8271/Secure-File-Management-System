from pathlib import Path
from typing import Tuple, Dict, List, Optional
import sqlite3
from datetime import datetime
import logging
from .security import SecurityManager
import json
import os

class SecureFileManager:
    def __init__(self, storage_path: str = "secure_storage", db_path: str = "secure_storage.db"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        self.db_path = db_path
        self.security = SecurityManager()
        self._initialize_database()
        self._setup_logging()

    def _initialize_database(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    filename TEXT,
                    owner_id TEXT,
                    encrypted BOOLEAN,
                    created_at TEXT,
                    modified_at TEXT,
                    file_path TEXT UNIQUE
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_permissions (
                    file_id TEXT,
                    user_id TEXT,
                    permission TEXT,
                    granted_at TEXT,
                    FOREIGN KEY (file_id) REFERENCES files(id),
                    UNIQUE(file_id, user_id)
                )
            """)

    def _setup_logging(self):
        logging.basicConfig(
            filename='file_operations.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _log_operation(self, user_id: str, action: str, file_id: Optional[str], status: str, metadata: Dict = None):
        try:
            with sqlite3.connect(self.db_path, timeout=20) as conn:
                # Create table if not exists
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        user_id TEXT,
                        action TEXT,
                        resource_id TEXT,
                        status TEXT,
                        additional_data TEXT
                    )
                """)

                # Also create activity_log table for user profile display
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS activity_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id TEXT,
                        operation TEXT,
                        resource_id TEXT,
                        timestamp TEXT,
                        status TEXT,
                        details TEXT
                    )
                """)
                
                # Insert into both tables for consistency
                current_time = datetime.now().isoformat()
                metadata_json = json.dumps(metadata or {})
                
                # Insert into audit_logs
                conn.execute("""
                    INSERT INTO audit_logs 
                    (timestamp, user_id, action, resource_id, status, additional_data) 
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    current_time,
                    user_id,
                    action,
                    file_id,
                    status,
                    metadata_json
                ))
                
                # Insert into activity_log
                conn.execute("""
                    INSERT INTO activity_log 
                    (user_id, operation, resource_id, timestamp, status, details) 
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    user_id,
                    action,
                    file_id,
                    current_time,
                    status,
                    metadata_json
                ))
                
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Database error in operation logging: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())

    def store_file(self, file_path: str, user_context: Dict, cloud_backup: bool = True, encryption_level: str = 'standard') -> Tuple[bool, str]:
        try:
            if not user_context or 'user_id' not in user_context:
                return False, "Invalid user context"
                
            source_path = Path(file_path)
            if not source_path.exists():
                return False, f"File not found: {file_path}"
            
            # Read and encrypt file with specified encryption level
            data = source_path.read_bytes()
            
            # Add encryption level to metadata
            metadata = {
                'encryption_level': encryption_level,
                'original_filename': source_path.name,
                'file_type': source_path.suffix.lower(),
                'encrypted_by': user_context['user_id'],
                'encrypted_at': datetime.now().isoformat()
            }
            
            encrypted_data = self.security.encrypt_file(data, metadata)
            
            # Generate secure file ID and path
            file_id = os.urandom(16).hex()
            dest_path = self.storage_path / f"{file_id}{source_path.suffix}"
            
            # Store encrypted file
            dest_path.write_bytes(encrypted_data)
            
            # Record in database with encryption metadata
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (file_id, source_path.name, user_context['user_id'], True,
                     datetime.now().isoformat(), datetime.now().isoformat(), str(dest_path))
                )
            
            self._log_operation(
                user_context['user_id'],
                'store',
                file_id,
                'success',
                {'encrypted': True, 'encryption_level': encryption_level}
            )
            
            return True, "File stored successfully"
            
        except Exception as e:
            logging.error(f"File storage error: {str(e)}")
            return False, f"Storage failed: {str(e)}"

    def decrypt_file(self, file_id: str, user_context: Dict) -> Tuple[bool, str, Optional[bytes]]:
        """
        Decrypt a file and return the decrypted content
        Returns: (success, message, decrypted_data)
        """
        try:
            if not user_context or 'user_id' not in user_context:
                return False, "Invalid user context", None
                
            logging.info(f"Starting file decryption process for file ID: {file_id}")
                
            # Verify file ownership and authorization
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT file_path, filename, owner_id FROM files WHERE id = ?",
                    (file_id,)
                )
                file_info = cursor.fetchone()
                
                if not file_info:
                    logging.warning(f"File not found in database: {file_id}")
                    return False, "File not found", None
                    
                file_path, filename, owner_id = file_info
                logging.info(f"File found: {filename}, path: {file_path}")
                
                # Authorization check: check if user is owner or has permissions
                is_authorized = False
                
                # Check if user is the owner
                if owner_id == user_context['user_id']:
                    is_authorized = True
                    logging.info(f"User is the owner of the file")
                else:
                    # Check if user has permission to access this file
                    cursor = conn.execute("""
                        SELECT permission_level FROM access_control 
                        WHERE resource_id = ? AND user_id = ? AND 
                        (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
                    """, (file_id, user_context['user_id']))
                    
                    permission = cursor.fetchone()
                    if permission and permission[0] in ('read', 'write', 'admin'):
                        is_authorized = True
                        logging.info(f"User has {permission[0]} permission for the file")
                
                if not is_authorized:
                    logging.warning(f"Unauthorized access attempt by user {user_context['user_id']} for file {file_id}")
                    self._log_operation(
                        user_context['user_id'],
                        'decrypt_unauthorized',
                        file_id,
                        'failed',
                        {'reason': 'unauthorized_access'}
                    )
                    return False, "Unauthorized access: you don't have permission to decrypt this file", None
                
                # Read and decrypt the file
                try:
                    # Check if file exists on disk
                    if not os.path.exists(file_path):
                        logging.error(f"File not found on disk: {file_path}")
                        return False, f"File not found on disk: {file_path}", None
                    
                    # Get file stat info for debugging
                    file_stat = os.stat(file_path)
                    logging.info(f"File size: {file_stat.st_size} bytes, modified: {datetime.fromtimestamp(file_stat.st_mtime)}")
                    
                    # Read the file with proper error handling
                    try:
                        encrypted_data = Path(file_path).read_bytes()
                        logging.info(f"Successfully read encrypted file, size: {len(encrypted_data)} bytes")
                        
                        # Log first 20 bytes of encrypted data for debugging
                        encrypted_header = encrypted_data[:20].hex() if encrypted_data else "No data"
                        logging.info(f"Encrypted data header: {encrypted_header}")
                    except Exception as read_error:
                        logging.error(f"Error reading file {file_path}: {str(read_error)}")
                        return False, f"Error reading encrypted file: {str(read_error)}", None
                    
                    # Decrypt the file data
                    try:
                        logging.info("Starting decryption with SecurityManager")
                        decrypted_data, metadata = self.security.decrypt_file(encrypted_data)
                        logging.info(f"Decryption successful, decrypted size: {len(decrypted_data)} bytes")
                        
                        # Log decrypted header for debugging
                        decrypted_header = decrypted_data[:20].hex() if decrypted_data else "No data"
                        logging.info(f"Decrypted data header: {decrypted_header}")
                        
                        # Log metadata
                        logging.info(f"File metadata: {metadata}")
                    except Exception as decrypt_error:
                        logging.error(f"Error in security.decrypt_file: {str(decrypt_error)}")
                        return False, f"Decryption failed: {str(decrypt_error)}", None
                    
                    # Log successful decryption
                    self._log_operation(
                        user_context['user_id'],
                        'decrypt',
                        file_id,
                        'success',
                        {'filename': filename}
                    )
                    
                    return True, "File decrypted successfully", decrypted_data
                    
                except Exception as inner_error:
                    logging.error(f"Inner decryption error: {str(inner_error)}")
                    import traceback
                    logging.error(traceback.format_exc())
                    return False, f"Decryption failed: {str(inner_error)}", None
                    
        except Exception as outer_error:
            logging.error(f"Outer file decryption error: {str(outer_error)}")
            import traceback
            logging.error(traceback.format_exc())
            return False, f"Decryption process failed: {str(outer_error)}", None

    def share_file(self, file_id: str, user_context: Dict, target_username: str, permission_level: str = 'read', expires_days: int = None) -> Tuple[bool, str]:
        """
        Share a file with another user by granting them access
        
        Args:
            file_id: ID of the file to share
            user_context: Context of the user sharing the file
            target_username: Username of the user to share with
            permission_level: Level of permission ('read', 'write', 'admin')
            expires_days: Optional number of days until permission expires
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if not user_context or 'user_id' not in user_context:
                return False, "Invalid user context"
                
            # Check if file exists and user has permission to share it
            with sqlite3.connect(self.db_path) as conn:
                # Ensure the access_control table exists
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS access_control (
                        resource_id TEXT,
                        user_id TEXT,
                        permission_level TEXT,
                        granted_by TEXT,
                        granted_at TEXT,
                        expires_at TEXT,
                        UNIQUE(resource_id, user_id)
                    )
                """)
                
                # First, get file information
                cursor = conn.execute(
                    "SELECT owner_id FROM files WHERE id = ?",
                    (file_id,)
                )
                file_info = cursor.fetchone()
                
                if not file_info:
                    return False, "File not found"
                
                owner_id = file_info[0]
                
                # Check if user is the owner or has admin permissions
                is_authorized = False
                if owner_id == user_context['user_id']:
                    is_authorized = True
                else:
                    # Check if user has admin permissions for this file
                    try:
                        cursor = conn.execute(
                            "SELECT permission_level FROM access_control WHERE resource_id = ? AND user_id = ?",
                            (file_id, user_context['user_id'])
                        )
                        perm = cursor.fetchone()
                        if perm and perm[0] == 'admin':
                            is_authorized = True
                    except sqlite3.Error:
                        # If table doesn't exist or there's another issue, just continue with is_authorized = False
                        pass
                
                if not is_authorized:
                    self._log_operation(
                        user_context['user_id'],
                        'share_unauthorized',
                        file_id,
                        'failed',
                        {'reason': 'unauthorized_access'}
                    )
                    return False, "You don't have permission to share this file"
                
                # Find the target user
                try:
                    cursor = conn.execute(
                        "SELECT id FROM users WHERE username = ?",
                        (target_username,)
                    )
                    target_user = cursor.fetchone()
                except sqlite3.Error:
                    return False, "Error accessing user database. Please try again later."
                
                if not target_user:
                    return False, f"User '{target_username}' not found"
                
                target_user_id = target_user[0]
                
                # Don't allow sharing with yourself
                if target_user_id == user_context['user_id']:
                    return False, "You can't share a file with yourself"
                
                # Calculate expiration date if provided
                expires_at = None
                if expires_days:
                    from datetime import datetime, timedelta
                    expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()
                
                # Check if permission already exists and update it, or create new
                try:
                    cursor = conn.execute(
                        "SELECT 1 FROM access_control WHERE resource_id = ? AND user_id = ?",
                        (file_id, target_user_id)
                    )
                    
                    if cursor.fetchone():
                        # Update existing permission
                        conn.execute(
                            """
                            UPDATE access_control 
                            SET permission_level = ?, granted_by = ?, granted_at = ?, expires_at = ?
                            WHERE resource_id = ? AND user_id = ?
                            """,
                            (permission_level, user_context['user_id'], datetime.now().isoformat(), expires_at, file_id, target_user_id)
                        )
                    else:
                        # Create new permission
                        conn.execute(
                            """
                            INSERT INTO access_control 
                            (resource_id, user_id, permission_level, granted_by, granted_at, expires_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (file_id, target_user_id, permission_level, user_context['user_id'], datetime.now().isoformat(), expires_at)
                        )
                except sqlite3.Error as e:
                    return False, f"Database error while updating permissions: {str(e)}"
                
                # Log the sharing action
                self._log_operation(
                    user_context['user_id'],
                    'share',
                    file_id,
                    'success',
                    {
                        'target_user': target_user_id,
                        'permission': permission_level,
                        'expires_at': expires_at
                    }
                )
                
                # Return success message with details
                expiry_msg = f" (expires in {expires_days} days)" if expires_days else " (never expires)"
                return True, f"File successfully shared with {target_username} with {permission_level} permission{expiry_msg}"
                
        except sqlite3.Error as e:
            logging.error(f"Database error in file sharing: {str(e)}")
            return False, f"Error sharing file: {str(e)}"
            
        except Exception as e:
            logging.error(f"Error sharing file: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            return False, f"Error sharing file: {str(e)}"

    def delete_file(self, file_id: str, user_context: Dict) -> Tuple[bool, str]:
        """
        Delete a file and its associated records
        
        Args:
            file_id: The ID of the file to delete
            user_context: Dictionary containing user information
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if not user_context or 'user_id' not in user_context:
                return False, "Invalid user context"
                
            # Verify file ownership and get file path
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT file_path, owner_id FROM files WHERE id = ?",
                    (file_id,)
                )
                file_info = cursor.fetchone()
                
                if not file_info:
                    return False, "File not found"
                    
                file_path, owner_id = file_info
                
                # Check if user is owner
                if owner_id != user_context['user_id']:
                    # Check if user has admin permission
                    cursor = conn.execute("""
                        SELECT permission_level FROM access_control 
                        WHERE resource_id = ? AND user_id = ? AND permission_level = 'admin'
                        AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
                    """, (file_id, user_context['user_id']))
                    
                    if not cursor.fetchone():
                        return False, "You don't have permission to delete this file"
                
                try:
                    # Delete the physical file
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    logging.error(f"Error deleting physical file: {str(e)}")
                    # Continue with database cleanup even if physical file deletion fails
                
                # Delete associated records
                conn.execute("DELETE FROM access_control WHERE resource_id = ?", (file_id,))
                conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
                conn.commit()
                
                # Log the operation
                self._log_operation(
                    user_context['user_id'],
                    'delete',
                    file_id,
                    'success',
                    {'file_path': file_path}
                )
                
                return True, "File deleted successfully"
                
        except Exception as e:
            logging.error(f"Error deleting file: {str(e)}")
            return False, f"Error deleting file: {str(e)}"
            return False, f"Error deleting file: {str(e)}"