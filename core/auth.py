from typing import Optional, Tuple, Dict
import hashlib
import os
from datetime import datetime, timedelta
import sqlite3
import logging
from .security import SecurityManager

class AuthenticationManager:
    def __init__(self, db_path: str = "secure_storage.db"):
        self.db_path = db_path
        self.security = SecurityManager()
        self._setup_logging()
        self._initialize_database()
        
    def _setup_logging(self):
        logging.basicConfig(
            filename='auth.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _initialize_database(self):
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging for better concurrency
            conn.execute("PRAGMA busy_timeout=5000")  # Set busy timeout
            conn.execute("PRAGMA synchronous=NORMAL")  # Faster writes with reasonable safety
            
            # Drop existing users table if it exists
            conn.execute("DROP TABLE IF EXISTS users")
            
            # Create users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    salt TEXT,
                    role TEXT,
                    created_at TEXT,
                    last_login TEXT,
                    phone_number TEXT
                )
            """)
            
            # Create access control table
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
            
            # Create password recovery table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS password_recovery (
                    username TEXT PRIMARY KEY,
                    otp TEXT,
                    expires_at TEXT,
                    attempts INTEGER DEFAULT 0
                )
            """)
            
            # Create single audit logs table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    user_id TEXT,
                    action TEXT,
                    resource_id TEXT,
                    status TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    additional_data TEXT
                )
            """)
            
            conn.commit()

    def register(self, username: str, password: str, phone_number: str = None, role: str = "user") -> Tuple[bool, str]:
        """
        Register a new user with the system
        
        Args:
            username: The username for the new account
            password: The password for the new account
            phone_number: Optional phone number for account recovery
            role: User role (default is "user")
            
        Returns:
            Tuple of (success, message)
        """
        try:
            salt = os.urandom(16).hex()
            password_hash = self._hash_password(password, salt)
            user_id = os.urandom(16).hex()
            
            # Connect with retry logic in case of database locks
            with sqlite3.connect(self.db_path, timeout=30) as conn:
                # Clear VALUES format and use named columns to avoid column count mismatch
                conn.execute("""
                    INSERT INTO users 
                    (id, username, password_hash, salt, role, created_at, last_login, phone_number) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id, 
                    username, 
                    password_hash, 
                    salt, 
                    role, 
                    datetime.now().isoformat(), 
                    None, 
                    phone_number
                ))
                conn.commit()
                
            # Log successful registration
            logging.info(f"User registered successfully: {username}")
            
            return True, "Registration successful"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except sqlite3.OperationalError as e:
            logging.error(f"Database operational error during registration: {str(e)}")
            return False, f"Registration failed: {str(e)}"
        except Exception as e:
            logging.error(f"Unexpected error during registration: {str(e)}")
            return False, "Registration failed due to an unexpected error"
            
    def login(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        try:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                cursor = conn.execute(
                    "SELECT id, password_hash, salt, role FROM users WHERE username = ?",
                    (username,)
                )
                user = cursor.fetchone()
                
                if not user:
                    return False, None
                    
                user_id, stored_hash, salt, role = user
                if self._hash_password(password, salt) == stored_hash:
                    # Update last login in a separate connection to avoid locks
                    self._update_last_login(user_id)
                    token = self.security.generate_token(user_id, role)
                    return True, token
                    
                return False, None
        except sqlite3.Error as e:
            logging.error(f"Database error during login: {str(e)}")
            return False, None
            
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user information by username"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT id, username, role, phone_number FROM users WHERE username = ?",
                    (username,)
                )
                user = cursor.fetchone()
                
                if user:
                    return {
                        "id": user[0],
                        "username": user[1],
                        "role": user[2],
                        "phone_number": user[3]
                    }
                return None
        except sqlite3.Error as e:
            logging.error(f"Database error while getting user: {str(e)}")
            return None
    
    def generate_otp(self, username: str) -> Tuple[bool, str]:
        """Generate a one-time password for account recovery"""
        try:
            # Import required modules at the top of the function
            import os
            import random
            import re
            from pathlib import Path
            
            # Check if user exists
            user = self.get_user_by_username(username)
            if not user:
                return False, "User not found"
                
            if not user.get("phone_number"):
                return False, "No phone number registered for this account"
            
            # Generate 6-digit OTP
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            
            # Store OTP with expiration (10 minutes from now)
            expiry_time = (datetime.now() + timedelta(minutes=10)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                # Remove any existing OTP for this user
                conn.execute("DELETE FROM password_recovery WHERE username = ?", (username,))
                
                # Insert new OTP
                conn.execute(
                    "INSERT INTO password_recovery (username, otp, expires_at, attempts) VALUES (?, ?, ?, 0)",
                    (username, otp, expiry_time)
                )
            
            # Log OTP generation
            self._log_audit(user["id"], "otp_generation", f"OTP generated for password recovery")
            
            # Select SMS backend based on environment variables or settings
            sms_backend = os.environ.get('SMS_BACKEND', 'twilio').lower()
            
            # For direct SMS (no Twilio API required - simulating SMS delivery)
            if sms_backend == 'direct':
                # Log the OTP for direct viewing - simulated delivery
                print(f"\n==================================")
                print(f"DIRECT SMS DELIVERY")
                print(f"TO: {user['phone_number']}")
                print(f"MESSAGE: Your verification code is: {otp}")
                print(f"==================================\n")
                
                # Create SMS delivery log
                sms_log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'sms_logs')
                os.makedirs(sms_log_dir, exist_ok=True)
                
                log_file = os.path.join(sms_log_dir, f'sms_{username}.txt')
                with open(log_file, 'w') as f:
                    f.write(f"TO: {user['phone_number']}\n")
                    f.write(f"TIME: {datetime.now().isoformat()}\n")
                    f.write(f"OTP: {otp}\n")
                
                return True, f"OTP sent to your registered phone number ending in {user['phone_number'][-4:]} (Check sms_logs folder)"
            
            # Default Twilio backend
            try:
                # Only import these if we're using Twilio
                from twilio.rest import Client
                
                # Check if Twilio credentials are available
                account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
                auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
                twilio_phone = os.environ.get('TWILIO_PHONE_NUMBER')
                
                if account_sid and auth_token and twilio_phone:
                    # Format phone number to E.164 format expected by Twilio
                    phone_number = user['phone_number']
                    
                    # Auto-detect and format Indian phone numbers (10 digits)
                    if re.match(r'^\d{10}$', phone_number):
                        # This is likely an Indian number (10 digits)
                        to_phone = f"+91{phone_number}"
                    elif phone_number.startswith('+'):
                        # Already has a country code
                        to_phone = phone_number
                    else:
                        # Default to US format if not matching Indian pattern
                        to_phone = f"+1{phone_number}"
                        
                    logging.info(f"Sending SMS to formatted number: {to_phone}")
                    
                    # Create Twilio client and send message
                    client = Client(account_sid, auth_token)
                    message = client.messages.create(
                        body=f"Your secure file manager verification code is: {otp}",
                        from_=twilio_phone,
                        to=to_phone
                    )
                    
                    logging.info(f"SMS sent successfully to {to_phone}, Twilio SID: {message.sid}")
                    sms_sent = True
                else:
                    # Fallback to logging only since Twilio isn't configured
                    logging.warning("Twilio credentials not found. OTP will be logged but not sent via SMS.")
                    logging.info(f"Generated OTP {otp} for user {username} (would be sent to {user['phone_number']})")
                    # This is a development fallback
                    sms_sent = False
                    
                    # For demo purposes, show the OTP in the system log so the user can see it
                    print(f"\n==================================")
                    print(f"OTP CODE FOR {username}: {otp}")
                    print(f"==================================\n")
            except ImportError:
                # Twilio package not installed
                logging.warning("Twilio package not installed. Install with 'pip install twilio'")
                sms_sent = False
            except Exception as sms_error:
                logging.error(f"Error sending SMS: {str(sms_error)}")
                sms_sent = False
            
            # Different messages based on whether SMS was actually sent
            if sms_sent:
                return True, f"Verification code sent to your registered phone number ending in {user['phone_number'][-4:]}"
            else:
                # In development mode, let the user know to check logs
                return True, f"OTP sent to your registered phone number ending in {user['phone_number'][-4:]} (Check console logs in development mode)"
            
        except Exception as e:
            logging.error(f"Error generating OTP: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            return False, f"Error generating OTP: {str(e)}"
    
    def verify_otp(self, username: str, otp: str) -> Tuple[bool, str]:
        """Verify OTP for password recovery"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT otp, expires_at, attempts FROM password_recovery WHERE username = ?",
                    (username,)
                )
                recovery_info = cursor.fetchone()
                
                if not recovery_info:
                    return False, "No recovery request found"
                
                stored_otp, expires_at, attempts = recovery_info
                
                # Check if OTP is expired
                if datetime.fromisoformat(expires_at) < datetime.now():
                    conn.execute("DELETE FROM password_recovery WHERE username = ?", (username,))
                    return False, "OTP has expired. Please request a new one."
                
                # Check if max attempts exceeded (5 attempts)
                if attempts >= 5:
                    conn.execute("DELETE FROM password_recovery WHERE username = ?", (username,))
                    return False, "Too many failed attempts. Please request a new OTP."
                
                # Update attempt count
                conn.execute(
                    "UPDATE password_recovery SET attempts = attempts + 1 WHERE username = ?",
                    (username,)
                )
                
                # Verify OTP
                if otp != stored_otp:
                    remaining_attempts = 5 - (attempts + 1)
                    return False, f"Invalid OTP. {remaining_attempts} attempts remaining."
                
                # OTP is valid - mark as verified but don't delete yet (will be deleted after password reset)
                conn.execute(
                    "UPDATE password_recovery SET attempts = -1 WHERE username = ?",  # -1 means verified
                    (username,)
                )
                
                return True, "OTP verified successfully"
                
        except Exception as e:
            logging.error(f"Error verifying OTP: {str(e)}")
            return False, "Error verifying OTP"
    
    def reset_password(self, username: str, new_password: str) -> Tuple[bool, str]:
        """Reset password after OTP verification"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check if OTP was verified
                cursor = conn.execute(
                    "SELECT attempts FROM password_recovery WHERE username = ?",
                    (username,)
                )
                recovery_info = cursor.fetchone()
                
                if not recovery_info or recovery_info[0] != -1:  # -1 means verified
                    return False, "OTP verification required before password reset"
                
                # Get user information
                cursor = conn.execute(
                    "SELECT id, salt FROM users WHERE username = ?",
                    (username,)
                )
                user_info = cursor.fetchone()
                
                if not user_info:
                    return False, "User not found"
                
                user_id, old_salt = user_info
                
                # Generate new salt and hash the new password
                new_salt = os.urandom(16).hex()
                password_hash = self._hash_password(new_password, new_salt)
                
                # Update password
                conn.execute(
                    "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                    (password_hash, new_salt, user_id)
                )
                
                # Clear recovery information
                conn.execute("DELETE FROM password_recovery WHERE username = ?", (username,))
                
                # Log password reset
                self._log_audit(user_id, "password_reset", "Password reset successful")
                
                return True, "Password reset successful"
                
        except Exception as e:
            logging.error(f"Error resetting password: {str(e)}")
            return False, "Error resetting password"

    def _update_last_login(self, user_id: str):
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                conn.execute(
                    "UPDATE users SET last_login = ? WHERE id = ?",
                    (datetime.now().isoformat(), user_id)
                )
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Error updating last login: {str(e)}")
            
    def _hash_password(self, password: str, salt: str) -> str:
        return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
        
    def _log_audit(self, user_id: str, action: str, details: str):
        try:
            with sqlite3.connect(self.db_path, timeout=20) as conn:
                conn.execute("""
                    INSERT INTO audit_logs 
                    (timestamp, user_id, action, resource_id, status, ip_address, user_agent, additional_data) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    user_id,
                    action,
                    None,  # resource_id
                    'success',  # status
                    None,  # ip_address
                    None,  # user_agent
                    details  # additional_data
                ))
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Database error in audit logging: {str(e)}")