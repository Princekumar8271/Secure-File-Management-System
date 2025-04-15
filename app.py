import os
import webbrowser
import sqlite3
import logging
import io
import json
import base64
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, Response, current_app, jsonify
from core.auth import AuthenticationManager
from core.file_manager import SecureFileManager
from core.face_auth import FaceAuthManager
from core.security import SecurityManager
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from pathlib import Path
import time
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Initialize managers
auth_manager = AuthenticationManager()
file_manager = SecureFileManager()
face_auth_manager = FaceAuthManager()

# Add this: modify request before processing to add is_xhr property
@app.before_request
def before_request():
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        request.is_xhr = True
    else:
        request.is_xhr = False

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'token' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        user_context = auth_manager.security.verify_token(session['token'])
        if not user_context:
            flash('Session expired. Please login again.', 'error')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

# Add a context processor to inject responsive design variables
@app.context_processor
def inject_responsive_meta():
    return {
        'viewport_meta': '<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">'
    }

@app.route('/')
def index():
    if 'token' in session:
        return redirect(url_for('dashboard'))
    return render_template('explanation.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Clear any existing authentication tokens when accessing login page
    if 'token' in session:
        session.pop('token', None)
    
    if request.method == 'POST':
        login_method = request.form.get('login_method', 'password')
        username = request.form['username']
        
        # First, check if the user exists and has face authentication set up
        user = auth_manager.get_user_by_username(username)
        if not user:
            flash('User not found.', 'error')
            return render_template('login.html')
            
        user_id = user['id']
        face_status = face_auth_manager.get_user_face_status(user_id)
        has_face_auth = face_status.get('registered', False)
        
        # Handle face login flow with password verification
        face_login_pending = request.form.get('face_login_pending') == 'true'
        
        if login_method == 'password' or face_login_pending:
            # Traditional password-based login
            password = request.form.get('password')
            if not password:
                flash('Please enter your password.', 'error')
                return render_template('login.html')
                
            success, token = auth_manager.login(username, password)
            if success:
                if has_face_auth:
                    # Store username and temporary token for face verification
                    session['pending_login_username'] = username
                    session['pending_token'] = token  # Store token temporarily
                    flash('Password verified. Please complete face verification for multi-factor authentication.', 'success')
                    return redirect(url_for('verify_face'))
                else:
                    # Only allow direct login if face auth is not set up
                    session['token'] = token
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials!', 'error')
                if face_login_pending:
                    return render_template('login.html', require_password=True, username=username)
                else:
                    return render_template('login.html')
        elif login_method == 'face':
            # Face-based login path - requires verification
            if not has_face_auth:
                flash('Face authentication not set up for this account. Please log in with your password first, then set up face authentication.', 'error')
                return render_template('login.html')
                
            # For face login, we need to verify their password first as well for proper MFA
            session['pending_login_username'] = username
            session['face_login_pending'] = True
            flash('Please enter your password for multi-factor authentication.', 'info')
            return render_template('login.html', require_password=True, username=username)
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')
        phone_number = request.form.get('phone')
        
        # Clean the phone number - remove spaces, dashes, parentheses, etc.
        if phone_number:
            import re
            # Remove any non-digit characters except leading +
            if phone_number.startswith('+'):
                # Keep the leading + but remove other non-digits
                phone_number = '+' + re.sub(r'\D', '', phone_number[1:])
            else:
                # Remove all non-digits
                phone_number = re.sub(r'\D', '', phone_number)
        
        # Basic validation
        errors = []
        
        # Check if passwords match
        if password != confirm_password:
            errors.append('Passwords do not match!')
        
        # Check password strength (basic check)
        if len(password) < 8:
            errors.append('Password must be at least 8 characters long')
            
        # Validate phone number - fix the validation to be more lenient
        if not phone_number or phone_number.strip() == '':
            errors.append('Please enter a phone number')
        else:
            # More relaxed validation - just check if it has enough digits
            digit_count = sum(1 for c in phone_number if c.isdigit())
            if digit_count < 10:
                errors.append('Phone number should have at least 10 digits')
        
        # If there are validation errors, show them
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html', 
                                  username=username, 
                                  phone_number=phone_number)
        
        # Try to register the user
        success, message = auth_manager.register(username, password, phone_number)
        
        if success:
            # Get the user ID for the newly registered user
            user = auth_manager.get_user_by_username(username)
            if user:
                # Log the user in automatically
                success, token = auth_manager.login(username, password)
                if success:
                    session['token'] = token
                    flash('Registration successful! Please set up face authentication to complete your account setup.', 'success')
                    return redirect(url_for('face_setup'))
            
            # Fallback if we couldn't auto-login
            flash('Registration successful! Please log in with your credentials.', 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
            # Return the form with the entered values (except password for security)
            return render_template('register.html', 
                                  username=username, 
                                  phone_number=phone_number)
    
    # GET request - just show the empty form
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
        
    try:
        # Get encrypted files for the user
        with sqlite3.connect(file_manager.db_path) as conn:
            cursor = conn.execute("""
                SELECT id, filename, created_at, encrypted, file_path 
                FROM files 
                WHERE owner_id = ? 
                ORDER BY created_at DESC
            """, (user_context['user_id'],))
            
            files = []
            for row in cursor.fetchall():
                file_id, filename, created_at, encrypted, file_path = row
                
                # Get encryption metadata if available
                encryption_info = "Standard"
                try:
                    if os.path.exists(file_path):
                        # Read just enough to get the metadata
                        with open(file_path, 'rb') as f:
                            container_data = f.read()
                            container = json.loads(base64.b64decode(container_data).decode())
                            metadata = container.get('metadata', {})
                            encryption_level = metadata.get('encryption_level', 'standard')
                            encryption_info = "High Security" if encryption_level == "high" else "Standard (AES-256)"
                except:
                    pass  # If we can't read metadata, use default
                
                files.append({
                    'id': file_id,
                    'filename': filename,
                    'date': datetime.fromisoformat(created_at).strftime('%Y-%m-%d %H:%M'),
                    'encrypted': encrypted,
                    'encryption_level': encryption_info
                })
        
        return render_template('dashboard.html', files=files)
        
    except sqlite3.Error as e:
        flash('Error loading files. Please try again.', 'error')
        logging.error(f"Database error: {str(e)}")
        return render_template('dashboard.html', files=[])

@app.route('/shared')
@login_required
def shared_files():
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
        
    try:
        # Get files shared with the user
        with sqlite3.connect(file_manager.db_path) as conn:
            # Ensure access_control table exists
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
            
            # Get files shared with the user, excluding expired permissions
            cursor = conn.execute("""
                SELECT f.id, f.filename, f.created_at, f.encrypted, f.file_path, 
                       u.username as owner_name, ac.permission_level, ac.granted_at, ac.expires_at
                FROM files f
                JOIN access_control ac ON f.id = ac.resource_id
                JOIN users u ON f.owner_id = u.id
                WHERE ac.user_id = ? AND 
                      (ac.expires_at IS NULL OR datetime(ac.expires_at) > datetime('now'))
                ORDER BY ac.granted_at DESC
            """, (user_context['user_id'],))
            
            shared_files = []
            for row in cursor.fetchall():
                file_id, filename, created_at, encrypted, file_path, owner_name, permission_level, granted_at, expires_at = row
                
                # Get encryption metadata if available
                encryption_info = "Standard"
                try:
                    if os.path.exists(file_path):
                        # Read just enough to get the metadata
                        with open(file_path, 'rb') as f:
                            container_data = f.read()
                            container = json.loads(base64.b64decode(container_data).decode())
                            metadata = container.get('metadata', {})
                            encryption_level = metadata.get('encryption_level', 'standard')
                            encryption_info = "High Security" if encryption_level == "high" else "Standard (AES-256)"
                except:
                    pass  # If we can't read metadata, use default
                
                shared_files.append({
                    'id': file_id,
                    'filename': filename,
                    'date': datetime.fromisoformat(created_at).strftime('%Y-%m-%d %H:%M'),
                    'encrypted': encrypted,
                    'encryption_level': encryption_info,
                    'owner': owner_name,
                    'permission': permission_level,
                    'granted_at': datetime.fromisoformat(granted_at).strftime('%Y-%m-%d %H:%M') if granted_at else '',
                    'expires_at': datetime.fromisoformat(expires_at).strftime('%Y-%m-%d %H:%M') if expires_at else 'Never'
                })
        
        return render_template('shared_files.html', shared_files=shared_files)
        
    except sqlite3.Error as e:
        flash('Error loading shared files. Please try again.', 'error')
        logging.error(f"Database error in shared files: {str(e)}")
        return render_template('shared_files.html', shared_files=[])

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'token' not in session:
        return redirect(url_for('login'))
        
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    # Simple profile info
    try:
        with sqlite3.connect(auth_manager.db_path) as conn:
            cursor = conn.execute(
                "SELECT username, role, phone_number, created_at, last_login FROM users WHERE id = ?",
                (user_context['user_id'],)
            )
            user_data = cursor.fetchone()
            
            if not user_data:
                flash('User profile not found', 'error')
                return redirect(url_for('dashboard'))
                
            username, role, phone_number, created_at, last_login = user_data
            
            # Create user preferences table if it doesn't exist
            conn.execute(
                """CREATE TABLE IF NOT EXISTS user_preferences (
                    user_id TEXT PRIMARY KEY,
                    theme TEXT DEFAULT 'light',
                    default_sort TEXT DEFAULT 'date',
                    show_extensions INTEGER DEFAULT 1,
                    default_share_permission TEXT DEFAULT 'read'
                )"""
            )
            
            # Check if preferences exist
            cursor = conn.execute(
                "SELECT * FROM user_preferences WHERE user_id = ?", 
                (user_context['user_id'],)
            )
            preferences = cursor.fetchone()
            
            # Insert default preferences if none exist
            if not preferences:
                conn.execute(
                    """INSERT INTO user_preferences 
                       (user_id, theme, default_sort, show_extensions, default_share_permission)
                       VALUES (?, 'light', 'date', 1, 'read')""",
                    (user_context['user_id'],)
                )
                conn.commit()
                
                # Get the newly inserted preferences
                cursor = conn.execute(
                    "SELECT * FROM user_preferences WHERE user_id = ?", 
                    (user_context['user_id'],)
                )
                preferences = cursor.fetchone()
            
            # Create a simple profile object
            profile = {
                'username': username,
                'role': role,
                'phone_number': phone_number,
                'created_at': datetime.fromisoformat(created_at).strftime('%Y-%m-%d %H:%M') if created_at else 'Unknown',
                'last_login': datetime.fromisoformat(last_login).strftime('%Y-%m-%d %H:%M') if last_login else 'Never',
                'preferences': {
                    'theme': preferences[1],
                    'default_sort': preferences[2],
                    'show_extensions': preferences[3],
                    'default_share_permission': preferences[4]
                }
            }
            
            # Create sessions table
            conn.execute(
                """CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    token_id TEXT,
                    created_at TEXT,
                    expires_at TEXT,
                    ip_address TEXT,
                    user_agent TEXT
                )"""
            )
            
            # Insert current session if not already present
            conn.execute(
                """INSERT OR IGNORE INTO user_sessions 
                   (user_id, token_id, created_at, expires_at)
                   VALUES (?, ?, ?, ?)""",
                (user_context['user_id'], 'current_session', 
                 datetime.now().isoformat(), 
                 (datetime.now() + timedelta(days=1)).isoformat())
            )
            conn.commit()
            
            # Get active sessions
            cursor = conn.execute(
                """SELECT created_at, expires_at FROM user_sessions 
                   WHERE user_id = ? ORDER BY created_at DESC LIMIT 5""",
                (user_context['user_id'],)
            )
            sessions_data = cursor.fetchall()
            
            active_sessions = []
            for session_data in sessions_data:
                created_at, expires_at = session_data
                active_sessions.append({
                    'created_at': datetime.fromisoformat(created_at).strftime('%Y-%m-%d %H:%M'),
                    'expires_at': datetime.fromisoformat(expires_at).strftime('%Y-%m-%d %H:%M')
                })
                
    except sqlite3.Error as e:
        logging.error(f"Database error in settings: {str(e)}")
        flash(f'Database error: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    
    # Handle settings form submissions
    if request.method == 'POST':
        setting_type = request.form.get('setting_type')
        
        try:
            # Profile settings
            if setting_type == 'profile':
                new_phone = request.form.get('phone_number')
                
                # Update phone number
                with sqlite3.connect(auth_manager.db_path) as conn:
                    conn.execute(
                        "UPDATE users SET phone_number = ? WHERE id = ?",
                        (new_phone, user_context['user_id'])
                    )
                    conn.commit()
                
                flash('Profile updated successfully', 'success')
                return redirect(url_for('settings'))
                
            # Password change
            elif setting_type == 'password':
                current_password = request.form.get('current_password')
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')
                
                # Verify current password
                with sqlite3.connect(auth_manager.db_path) as conn:
                    cursor = conn.execute(
                        "SELECT password_hash, salt FROM users WHERE id = ?",
                        (user_context['user_id'],)
                    )
                    stored_hash, salt = cursor.fetchone()
                    
                    if auth_manager._hash_password(current_password, salt) != stored_hash:
                        flash('Current password is incorrect', 'error')
                        return redirect(url_for('settings'))
                
                # Validate new password
                if new_password != confirm_password:
                    flash('New passwords do not match', 'error')
                    return redirect(url_for('settings'))
                    
                if len(new_password) < 8:
                    flash('Password must be at least 8 characters long', 'error')
                    return redirect(url_for('settings'))
                
                # Update password
                new_salt = os.urandom(16).hex()
                new_hash = auth_manager._hash_password(new_password, new_salt)
                
                with sqlite3.connect(auth_manager.db_path) as conn:
                    conn.execute(
                        "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                        (new_hash, new_salt, user_context['user_id'])
                    )
                    conn.commit()
                
                flash('Password updated successfully', 'success')
                return redirect(url_for('settings'))
                
            # Preferences
            elif setting_type == 'preferences':
                theme = request.form.get('theme', 'light')
                default_sort = request.form.get('default_sort', 'date')
                show_extensions = 1 if request.form.get('show_extensions') else 0
                default_share = request.form.get('default_share', 'read')
                
                # Update preferences
                with sqlite3.connect(auth_manager.db_path) as conn:
                    conn.execute(
                        """UPDATE user_preferences 
                           SET theme = ?, default_sort = ?, show_extensions = ?, 
                              default_share_permission = ?
                           WHERE user_id = ?""",
                        (theme, default_sort, show_extensions, default_share, user_context['user_id'])
                    )
                    conn.commit()
                
                flash('Preferences updated successfully', 'success')
                return redirect(url_for('settings'))
        
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            logging.error(f"Error in settings update: {str(e)}")
    
    return render_template('settings.html', profile=profile, active_sessions=active_sessions)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'token' not in session:
        return redirect(url_for('login'))
        
    # Decode token to get user context
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
        
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))
        
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))
    
    # Get encryption level from form
    encryption_level = request.form.get('encryption_level', 'standard')
    
    # Save file temporarily and process
    temp_path = os.path.join('temp', file.filename)
    file.save(temp_path)
    
    # Pass encryption level to the file manager
    success, message = file_manager.store_file(
        temp_path, 
        user_context, 
        encryption_level=encryption_level
    )
    
    os.remove(temp_path)  # Clean up
    
    flash(message, 'success' if success else 'error')
    return redirect(url_for('dashboard', action='upload', success=success))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        if not username:
            flash('Please enter your username.', 'error')
            return render_template('forgot_password.html')
            
        # Generate OTP for password reset
        success, message = auth_manager.generate_otp(username)
        if success:
            flash(message, 'success')
            return redirect(url_for('verify_otp', username=username))
        else:
            # Don't reveal if user exists for security reasons
            if message == "User not found":
                flash('If your account exists, a verification code has been sent to your registered phone number.', 'info')
            else:
                flash(message, 'error')
            return render_template('forgot_password.html')
            
    return render_template('forgot_password.html')

@app.route('/reset_password/<username>', methods=['GET', 'POST'])
def reset_password(username):
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or not confirm_password:
            flash('Please enter both password fields.', 'error')
            return render_template('reset_password.html', username=username)
            
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', username=username)
            
        # Check password strength
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('reset_password.html', username=username)
            
        # Reset the password using auth manager
        success, message = auth_manager.reset_password(username, password)
        if success:
            flash('Your password has been reset successfully. You can now login with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
            return render_template('reset_password.html', username=username)
    
    return render_template('reset_password.html', username=username)

@app.route('/verify_face', methods=['GET', 'POST'])
def verify_face():
    # Check if there's a pending login
    if 'pending_login_username' not in session:
        flash('No pending login to verify.', 'error')
        return redirect(url_for('login'))
    
    username = session['pending_login_username']
    
    # Get user by username
    user = auth_manager.get_user_by_username(username)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))
        
    user_id = user['id']
    
    # Check if user has face auth set up
    has_face_auth = face_auth_manager.has_face_auth(user_id)
    if not has_face_auth:
        flash('Face authentication not set up for this account. Please log in with your password first, then set up face authentication.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Process the face verification
        if 'face_image' not in request.files:
            flash('No face image provided.', 'error')
            return render_template('face_verify.html', username=username)
        
        file = request.files['face_image']
        
        if file.filename == '':
            flash('No face image selected.', 'error')
            return render_template('face_verify.html', username=username)
        
        try:
            # Get user information
            user = auth_manager.get_user_by_username(username)
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('login'))
            
            user_id = user['id']
            
            # Read the image data
            image_data = file.read()
            
            # Verify face
            success, message = face_auth_manager.verify_face(user_id, image_data, username=username)
            
            if success:
                # Complete the login
                if 'pending_token' in session:
                    session['token'] = session.pop('pending_token')
                    session.pop('pending_login_username', None)
                    if 'face_login_pending' in session:
                        session.pop('face_login_pending', None)
                        
                    flash('Face verification successful. Welcome back!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Session expired. Please login again.', 'error')
                    return redirect(url_for('login'))
            else:
                flash(f'Face verification failed: {message}', 'error')
                return render_template('face_verify.html', username=username)
        except Exception as e:
            logging.error(f"Error processing face verification: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            flash(f"Error processing face verification: {str(e)}", 'error')
            return render_template('face_verify.html', username=username)
    
    # GET request - show the face verification page
    return render_template('face_verify.html', username=username)

@app.route('/verify_face_complete', methods=['POST'])
def verify_face_complete():
    if 'pending_login_username' not in session:
        flash('No pending login to verify.', 'error')
        return redirect(url_for('login'))
    
    # This endpoint is hit from the face_capture.html form submission
    if 'image_data' not in request.form:
        flash('No face data provided.', 'error')
        return redirect(url_for('verify_face'))
    
    try:
        username = session['pending_login_username']
        user = auth_manager.get_user_by_username(username)
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('login'))
        
        user_id = user['id']
        
        # Get the image data from the form
        image_data = base64.b64decode(request.form['image_data'].split(',')[1])
        
        # Verify face
        success, message = face_auth_manager.verify_face(user_id, image_data, username=username)
        
        if success:
            # Complete the login
            if 'pending_token' in session:
                session['token'] = session.pop('pending_token')
                session.pop('pending_login_username', None)
                if 'face_login_pending' in session:
                    session.pop('face_login_pending', None)
                    
                flash('Face verification successful. Welcome back!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Session expired. Please login again.', 'error')
                return redirect(url_for('login'))
        else:
            flash(f'Face verification failed: {message}', 'error')
            return redirect(url_for('verify_face'))
    except Exception as e:
        logging.error(f"Error processing face verification: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        flash(f"Error processing face verification. Please try again.", 'error')
    
    return redirect(url_for('verify_face'))

@app.route('/face_setup', methods=['GET'])
@login_required
def face_setup():
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    # Check if user already has face auth set up
    face_status = face_auth_manager.get_user_face_status(user_context['user_id'])
    
    # Render the face registration page with is_new_registration flag
    return render_template('face_register.html', 
                          face_status=face_status, 
                          is_new_registration=True)

@app.route('/check_face_auth', methods=['GET'])
def check_face_auth():
    """AJAX endpoint to check if a user has face authentication set up"""
    username = request.args.get('username')
    if not username:
        return jsonify({'has_face_auth': False, 'error': 'No username provided'})
    
    # Get user by username
    user = auth_manager.get_user_by_username(username)
    if not user:
        return jsonify({'has_face_auth': False, 'error': 'User not found'})
    
    # Check if user has face auth set up
    has_face_auth = face_auth_manager.has_face_auth(user['id'])
    
    return jsonify({'has_face_auth': has_face_auth})

@app.route('/register_face', methods=['GET', 'POST'])
@login_required
def register_face():
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Process face registration
        if 'image_data' not in request.form:
            flash('No face data provided.', 'error')
            return render_template('face_capture.html', action='register')
        
        try:
            # Get the image data from the form
            image_data_str = request.form['image_data']
            
            # Debug information
            logging.info(f"Received image data. Length: {len(image_data_str)}")
            if len(image_data_str) < 100:
                flash('Invalid image data received. Please try again.', 'error')
                return render_template('face_capture.html', action='register')
            
            # Properly decode the image data
            if ',' in image_data_str:  # Handle data URL format
                image_data = base64.b64decode(image_data_str.split(',')[1])
            else:  # Handle raw base64
                try:
                    image_data = base64.b64decode(image_data_str)
                except Exception as e:
                    logging.error(f"Error decoding base64 data: {str(e)}")
                    flash(f'Error processing image: {str(e)}', 'error')
                    return render_template('face_capture.html', action='register')
            
            # Register face
            success, message = face_auth_manager.register_face(user_context['user_id'], image_data, username=user_context.get('username'))
            
            if success:
                flash('Face registered successfully! Please login to continue.', 'success')
                # Log the user out to ensure proper authentication flow
                session.pop('token', None)
                return redirect(url_for('login'))
            else:
                flash(f'Face registration failed: {message}', 'error')
                return render_template('face_capture.html', action='register')
        except Exception as e:
            logging.error(f"Error registering face: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            flash(f"Error registering face: {str(e)}", 'error')
            return render_template('face_capture.html', action='register')
    
    # GET request - show the face registration page
    return render_template('face_capture.html', action='register')

@app.route('/face_capture/<action>', methods=['GET'])
def face_capture(action):
    if action not in ['register', 'verify']:
        flash('Invalid action specified.', 'error')
        return redirect(url_for('dashboard'))
    
    # For verification, check if there's a pending login
    if action == 'verify' and 'pending_login_username' not in session:
        flash('No pending login to verify.', 'error')
        return redirect(url_for('login'))
    
    # For registration, check if user is logged in
    if action == 'register':
        if 'token' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        user_context = auth_manager.security.verify_token(session['token'])
        if not user_context:
            flash('Session expired. Please login again.', 'error')
            return redirect(url_for('login'))
    
    return render_template('face_capture.html', action=action)

@app.route('/delete_face', methods=['POST'])
@login_required
def delete_face():
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    try:
        # Delete face data
        success, message = face_auth_manager.delete_face_data(user_context['user_id'])
        if success:
            flash('Face authentication disabled successfully.', 'success')
        else:
            flash(f'Error disabling face authentication: {message}', 'error')
    except Exception as e:
        logging.error(f"Error deleting face data: {str(e)}")
        flash(f'Error disabling face authentication: {str(e)}', 'error')
    
    # Redirect to appropriate page based on referer
    referer = request.referrer
    if referer and 'face_register' in referer:
        return redirect(url_for('dashboard'))
    elif referer and 'user_profile' in referer:
        return redirect(url_for('user_profile'))
    else:
        return redirect(url_for('settings'))

@app.route('/user_profile')
@login_required
def user_profile():
    if 'token' not in session:
        flash('Please log in to access this page.', 'error')
        return redirect(url_for('login'))

    try:
        user_context = auth_manager.security.verify_token(session['token'])
        if not user_context or not isinstance(user_context, dict):
            session.clear()
            flash('Session expired. Please login again.', 'error')
            return redirect(url_for('login'))

        user_id = user_context.get('user_id')
        if not user_id:
            session.clear()
            flash('Invalid session. Please login again.', 'error')
            return redirect(url_for('login'))

        # Get user info
        with sqlite3.connect(auth_manager.db_path) as conn:
            # Ensure activity_log table exists
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
            conn.commit()
            
            cursor = conn.execute(
                "SELECT id, username, role, phone_number, created_at, last_login FROM users WHERE id = ?",
                (user_id,)
            )
            user_data = cursor.fetchone()
            
            if not user_data:
                flash('User profile not found', 'error')
                return redirect(url_for('dashboard'))
                
            user_id, username, role, phone_number, created_at, last_login = user_data
            
            # Get face authentication status with error handling
            try:
                face_status = face_auth_manager.get_user_face_status(user_id)
                if face_status is None or not isinstance(face_status, dict):
                    face_status = {}
            except Exception as e:
                logging.error(f"Error getting face status: {str(e)}")
                face_status = {}
            
            # Get activity logs - with error handling
            try:
                cursor = conn.execute(
                    """SELECT operation, timestamp, details FROM activity_log 
                       WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5""",
                    (user_id,)
                )
                recent_activities = []
                for row in cursor.fetchall():
                    op, ts, details = row
                    try:
                        details_dict = json.loads(details) if details else {}
                    except:
                        details_dict = {}
                        
                    recent_activities.append({
                        'operation': op,
                        'timestamp': datetime.fromisoformat(ts).strftime('%Y-%m-%d %H:%M') if ts else 'Unknown',
                        'details': details_dict
                    })
            except sqlite3.Error as e:
                logging.error(f"Database error when fetching activity logs: {str(e)}")
                recent_activities = []
                
            # Get file stats - with error handling
            try:
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM files WHERE owner_id = ?",
                    (user_id,)
                )
                file_count = cursor.fetchone()[0]
                
                # Ensure access_control table exists
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
                
                cursor = conn.execute(
                    """SELECT COUNT(*) FROM access_control ac
                       JOIN files f ON ac.resource_id = f.id
                       WHERE f.owner_id = ?""",
                    (user_id,)
                )
                shared_count = cursor.fetchone()[0]
            except sqlite3.Error as e:
                logging.error(f"Database error when fetching file stats: {str(e)}")
                file_count = 0
                shared_count = 0
            
            # Create profile object
            profile = {
                'user_id': user_id,
                'username': username,
                'role': role,
                'phone_number': phone_number,
                'created_at': datetime.fromisoformat(created_at).strftime('%Y-%m-%d') if created_at else 'Unknown',
                'last_login': datetime.fromisoformat(last_login).strftime('%Y-%m-%d %H:%M') if last_login else 'Never',
                'face_enabled': face_status.get('registered', False),
                'file_count': file_count,
                'shared_count': shared_count
            }
            
        return render_template('user_profile.html', profile=profile, recent_activities=recent_activities)
            
    except Exception as e:
        logging.error(f"Error loading user profile: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        flash(f'Error loading profile: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/activity_log')
@login_required
def activity_log():
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    try:
        # Ensure activity_log table exists
        with sqlite3.connect(auth_manager.db_path) as conn:
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
            conn.commit()
            
            # Get activity logs with better error handling
            try:
                cursor = conn.execute(
                    """SELECT operation, resource_id, timestamp, status, details FROM activity_log 
                       WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100""",
                    (user_context['user_id'],)
                )
                
                activities = []
                for row in cursor.fetchall():
                    operation, resource_id, timestamp, status, details = row
                    try:
                        details_dict = json.loads(details) if details else {}
                    except:
                        details_dict = {}
                        
                    activities.append({
                        'operation': operation,
                        'resource_id': resource_id,
                        'timestamp': datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else 'Unknown',
                        'status': status,
                        'details': details_dict
                    })
            except sqlite3.Error as e:
                logging.error(f"Database error when fetching activity logs: {str(e)}")
                activities = []
                flash(f'Some activity data could not be loaded.', 'warning')
            
        return render_template('activity_log.html', activities=activities)
        
    except Exception as e:
        logging.error(f"Error loading activity log: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
        flash(f'Error loading activity log: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/verify_otp/<username>', methods=['GET', 'POST'])
def verify_otp(username):
    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:
            flash('Please enter the OTP.', 'error')
            return render_template('verify_otp.html', username=username)
            
        # Verify OTP using the auth manager
        success, message = auth_manager.verify_otp(username, otp)
        if success:
            flash('OTP verified successfully! You can now reset your password.', 'success')
            return redirect(url_for('reset_password', username=username))
        else:
            flash(message, 'error')
            return render_template('verify_otp.html', username=username)
            
    return render_template('verify_otp.html', username=username)

@app.route('/disable_otp', methods=['POST'])
@login_required
def disable_otp():
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    # Disable OTP logic would go here
    # For now, just simulate success
    flash('Two-factor authentication disabled successfully.', 'success')
    return redirect(url_for('user_profile'))

@app.route('/share_file/<file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
        
    try:
        # Check if user is the owner of the file
        with sqlite3.connect(file_manager.db_path) as conn:
            cursor = conn.execute(
                """SELECT f.id, f.filename, f.owner_id, u.username as owner_name
                   FROM files f
                   JOIN users u ON f.owner_id = u.id 
                   WHERE f.id = ?""", 
                (file_id,)
            )
            file_info = cursor.fetchone()
            
            if not file_info:
                flash('File not found.', 'error')
                return redirect(url_for('dashboard'))
            
            file_id, filename, owner_id, owner_name = file_info
            
            # Check ownership or admin permission
            is_owner = owner_id == user_context['user_id']
            
            if not is_owner:
                # Check if user has admin permission
                cursor = conn.execute(
                    """SELECT permission_level FROM access_control 
                       WHERE resource_id = ? AND user_id = ? AND permission_level = 'admin'""",
                    (file_id, user_context['user_id'])
                )
                admin_permission = cursor.fetchone() is not None
                
                if not admin_permission:
                    flash('You do not have permission to share this file.', 'error')
                    return redirect(url_for('dashboard'))
            
            # Get current shares
            cursor = conn.execute(
                """SELECT u.username, ac.permission_level, ac.granted_at, ac.expires_at
                   FROM access_control ac
                   JOIN users u ON ac.user_id = u.id
                   WHERE ac.resource_id = ?""",
                (file_id,)
            )
            
            current_shares = []
            for row in cursor.fetchall():
                username, permission, granted_at, expires_at = row
                
                # Skip the owner in the list
                if username == user_context['username']:
                    continue
                    
                current_shares.append({
                    'username': username,
                    'permission': permission,
                    'granted_at': datetime.fromisoformat(granted_at).strftime('%Y-%m-%d') if granted_at else 'Unknown',
                    'expires_at': datetime.fromisoformat(expires_at).strftime('%Y-%m-%d') if expires_at else 'Never'
                })
            
            # Process form submission
            if request.method == 'POST':
                username = request.form.get('username')
                permission = request.form.get('permission', 'read')
                expires_days = request.form.get('expires', '')
                
                if not username:
                    flash('Please enter a username to share with.', 'error')
                    return render_template('share.html', file_id=file_id, filename=filename, 
                                         current_shares=current_shares, is_owner=is_owner)
                
                # Check if user exists
                cursor = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                
                if not user:
                    flash(f'User "{username}" not found.', 'error')
                    return render_template('share.html', file_id=file_id, filename=filename, 
                                         current_shares=current_shares, is_owner=is_owner)
                
                target_user_id = user[0]
                
                # Validate parameters
                if permission not in ['read', 'write', 'admin']:
                    permission = 'read'  # Default to read
                
                expires_at = None
                if expires_days and expires_days.isdigit():
                    expires_at = (datetime.now() + timedelta(days=int(expires_days))).isoformat()
                
                # Share the file
                success, message = file_manager.share_file(
                    file_id, 
                    user_context, 
                    username, 
                    permission_level=permission, 
                    expires_days=int(expires_days) if expires_days and expires_days.isdigit() else None
                )
                
                if success:
                    flash(f'File shared successfully with {username}.', 'success')
                else:
                    flash(f'Error sharing file: {message}', 'error')
                
                # Redirect to refresh the page with updated shares
                return redirect(url_for('share_file', file_id=file_id))
            
            # Render the share page
            return render_template('share.html', file_id=file_id, filename=filename, 
                                 current_shares=current_shares, is_owner=is_owner)
    
    except Exception as e:
        logging.error(f"Error in share_file: {str(e)}")
        flash(f'Error sharing file: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/download-decrypted')
@login_required
def download_decrypted():
    # Check if there's a pending download in the session
    if 'pending_download' not in session:
        flash('No pending download found.', 'error')
        return redirect(url_for('dashboard'))
    
    download_info = session.pop('pending_download')  # Remove from session after retrieving
    
    try:
        # Check if the temporary file exists
        if not os.path.exists(download_info['path']):
            flash('Download expired. Please try decrypting again.', 'error')
            return redirect(url_for('dashboard'))
        
        # Read the file data
        with open(download_info['path'], 'rb') as f:
            file_data = f.read()
        
        # Create a BytesIO object
        data_io = io.BytesIO(file_data)
        
        # Delete the temporary file
        os.remove(download_info['path'])
        
        # Send the file to the user
        return send_file(
            data_io,
            mimetype=download_info['mime_type'],
            as_attachment=True,
            download_name=download_info['filename']
        )
    
    except Exception as e:
        logging.error(f"Error during download: {str(e)}")
        flash('Error downloading file.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'token' not in session:
        return redirect(url_for('login'))
        
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    try:
        with sqlite3.connect(file_manager.db_path) as conn:
            # First check if user is the owner
            cursor = conn.execute(
                "SELECT filename, file_path FROM files WHERE id = ? AND owner_id = ?",
                (file_id, user_context['user_id'])
            )
            file_info = cursor.fetchone()
            
            # If user is not the owner, check if they have access through sharing
            if not file_info:
                cursor = conn.execute("""
                    SELECT f.filename, f.file_path 
                    FROM files f
                    JOIN access_control ac ON f.id = ac.resource_id
                    WHERE f.id = ? AND ac.user_id = ? AND 
                          (ac.expires_at IS NULL OR datetime(ac.expires_at) > datetime('now'))
                """, (file_id, user_context['user_id']))
                file_info = cursor.fetchone()
            
            if not file_info:
                flash('File not found or access denied.', 'error')
                # Redirect to the referer page or dashboard if referer is not available
                referer = request.referrer
                if referer and 'shared' in referer:
                    return redirect(url_for('shared_files'))
                return redirect(url_for('dashboard'))
            
            filename, file_path = file_info
            return send_file(
                file_path,
                download_name=filename,
                as_attachment=True
            )
    except Exception as e:
        logging.error(f"Download error: {str(e)}")
        flash('Error downloading file.', 'error')
        # Redirect to the referer page or dashboard if referer is not available
        referer = request.referrer
        if referer and 'shared' in referer:
            return redirect(url_for('shared_files'))
        return redirect(url_for('dashboard'))

@app.route('/decrypt/<file_id>', methods=['POST'])
@login_required
def decrypt_file(file_id):
    success = False
    try:
        user_context = auth_manager.security.verify_token(session['token'])
        if not user_context:
            flash('Session expired. Please login again.', 'error')
            return redirect(url_for('login'))
            
        # Get file info from file_manager
        with sqlite3.connect(file_manager.db_path) as conn:
            # First check if original_filename column exists in the files table
            cursor = conn.execute("PRAGMA table_info(files)")
            columns = [info[1] for info in cursor.fetchall()]
            
            # Adjust query based on available columns
            if 'original_filename' in columns:
                query = "SELECT owner_id, file_path, filename, original_filename, mime_type, file_type FROM files WHERE id = ?"
            else:
                query = "SELECT owner_id, file_path, filename FROM files WHERE id = ?"
            
            cursor = conn.execute(query, (file_id,))
            file_info = cursor.fetchone()
            
            if not file_info:
                flash('File not found.', 'error')
                return redirect(url_for('dashboard'))
            
            # Extract file info based on available columns
            if 'original_filename' in columns:
                owner_id, file_path, filename, original_filename, mime_type, file_type = file_info
            else:
                owner_id, file_path, filename = file_info
                original_filename = filename
                mime_type = 'application/octet-stream'
                file_type = os.path.splitext(filename)[1].strip('.') or 'bin'
            
            # Verify ownership
            if owner_id != user_context['user_id']:
                # Check if user has permission through sharing
                cursor = conn.execute("""
                    SELECT 1 FROM access_control 
                    WHERE resource_id = ? AND user_id = ? AND 
                          (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
                """, (file_id, user_context['user_id']))
                
                if not cursor.fetchone():
                    flash('You do not have permission to decrypt this file.', 'error')
                    return redirect(url_for('dashboard'))
            
            # Get decryption password
            password = request.form.get('password')
            if not password:
                flash('No password provided.', 'error')
                return redirect(url_for('dashboard'))
                
            # Get user's stored password information for verification
            cursor = conn.execute(
                "SELECT salt, password_hash FROM users WHERE id = ?",
                (user_context['user_id'],)
            )
            user_auth_info = cursor.fetchone()
            
            if not user_auth_info:
                flash('Authentication error: User information not found.', 'error')
                return redirect(url_for('dashboard'))
                
            salt, stored_hash = user_auth_info
            
            # Verify that the provided password matches user's login password
            password_hash = hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
            if password_hash != stored_hash:
                flash('Incorrect password. Your login password is required for decryption.', 'error')
                return redirect(url_for('dashboard'))
            
            try:
                # Read the encrypted file
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # Decrypt the data
                security_manager = SecurityManager()
                try:
                    container = json.loads(base64.b64decode(encrypted_data).decode())
                    encrypted_data = base64.b64decode(container['data'].encode())
                    
                    # Try to decrypt with the provided password
                    # Create a key from the password
                    key = hashlib.sha256(password.encode()).digest()
                    key = base64.urlsafe_b64encode(key)
                    
                    try:
                        # First try with the provided password
                        cipher = Fernet(key)
                        decrypted_data = cipher.decrypt(encrypted_data)
                        logging.info("Decryption with provided password successful")
                    except Exception as e:
                        logging.warning(f"Password decryption failed: {str(e)}")
                        # Try with container key if available
                        if 'key' in container:
                            try:
                                container_key = container['key'].encode() if isinstance(container['key'], str) else container['key']
                                cipher = Fernet(container_key)
                                decrypted_data = cipher.decrypt(encrypted_data)
                                logging.info("Decryption with container key successful")
                            except Exception as e:
                                logging.error(f"Container key decryption failed: {str(e)}")
                                flash('Decryption failed. Please try again.', 'error')
                                return redirect(url_for('dashboard'))
                        else:
                            flash('Decryption failed. Please try again.', 'error')
                            return redirect(url_for('dashboard'))
                except Exception as e:
                    logging.error(f"Error processing container: {str(e)}")
                    flash(f'Error decrypting file: invalid format or corrupted file.', 'error')
                    return redirect(url_for('dashboard'))
                
                # Create temp directory if it doesn't exist
                temp_dir = os.path.join('temp')
                os.makedirs(temp_dir, exist_ok=True)
                
                # Create a unique filename for the decrypted file
                actual_file_type = file_type if file_type else os.path.splitext(filename)[1].strip('.') or 'bin'
                temp_path = os.path.join(temp_dir, f"{file_id}_{int(time.time())}.{actual_file_type}")
                
                # Save decrypted data to temp file
                with open(temp_path, 'wb') as f:
                    f.write(decrypted_data)
                
                # If we have metadata in the container, try to use it
                if 'metadata' in container and isinstance(container['metadata'], dict):
                    metadata = container['metadata']
                    # Use original filename from metadata if available
                    if 'original_filename' in metadata:
                        original_filename = metadata['original_filename']
                    # Use mime type from metadata if available
                    if 'mime_type' in metadata:
                        mime_type = metadata['mime_type']
                
                # Store download info in session
                session['pending_download'] = {
                    'path': temp_path,
                    'filename': original_filename or filename,
                    'mime_type': mime_type or 'application/octet-stream'
                }
                
                # Log successful decryption
                logging.info(f"User {user_context.get('username', 'unknown')} successfully decrypted file {file_id}")
                
                success = True
                
                # Redirect to download route
                return redirect(url_for('download_decrypted'))
                
            except Exception as e:
                logging.error(f"Error decrypting file: {str(e)}")
                import traceback
                logging.error(traceback.format_exc())
                flash(f'Error decrypting file: {str(e)}', 'error')
                
    except Exception as e:
        logging.error(f"Error in decrypt_file: {str(e)}")
        flash(f'Error decrypting file: {str(e)}', 'error')
        
    return redirect(url_for('dashboard'))

@app.route('/decrypt_shared/<file_id>', methods=['POST'])
@login_required
def decrypt_shared_file(file_id):
    success = False
    try:
        user_context = auth_manager.security.verify_token(session['token'])
        if not user_context:
            flash('Session expired. Please login again.', 'error')
            return redirect(url_for('login'))
            
        # Verify that this is a shared file for this user
        with sqlite3.connect(file_manager.db_path) as conn:
            # First check if original_filename column exists in the files table
            cursor = conn.execute("PRAGMA table_info(files)")
            columns = [info[1] for info in cursor.fetchall()]
            
            # Adjust query based on available columns
            base_query = """
                SELECT f.filename, f.file_path{} 
                FROM files f
                JOIN access_control ac ON f.id = ac.resource_id
                WHERE f.id = ? AND ac.user_id = ? AND 
                      (ac.expires_at IS NULL OR datetime(ac.expires_at) > datetime('now'))
            """
            
            if all(col in columns for col in ['original_filename', 'mime_type', 'file_type']):
                query = base_query.format(", f.original_filename, f.mime_type, f.file_type")
            else:
                query = base_query.format("")
            
            cursor = conn.execute(query, (file_id, user_context['user_id']))
            file_info = cursor.fetchone()
            
            if not file_info:
                flash('File not found or access denied.', 'error')
                return redirect(url_for('shared_files'))
            
            # Extract file info based on available columns
            if all(col in columns for col in ['original_filename', 'mime_type', 'file_type']):
                filename, file_path, original_filename, mime_type, file_type = file_info
            else:
                filename, file_path = file_info
                original_filename = filename
                mime_type = 'application/octet-stream'
                file_type = os.path.splitext(filename)[1].strip('.') or 'bin'
            
            # Get decryption password
            password = request.form.get('password')
            if not password:
                flash('No password provided.', 'error')
                return redirect(url_for('shared_files'))
                
            # Get user's stored password information for verification
            cursor = conn.execute(
                "SELECT salt, password_hash FROM users WHERE id = ?",
                (user_context['user_id'],)
            )
            user_auth_info = cursor.fetchone()
            
            if not user_auth_info:
                flash('Authentication error: User information not found.', 'error')
                return redirect(url_for('shared_files'))
                
            salt, stored_hash = user_auth_info
            
            # Verify that the provided password matches user's login password
            password_hash = hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
            if password_hash != stored_hash:
                flash('Incorrect password. Your login password is required for decryption.', 'error')
                return redirect(url_for('shared_files'))
            
            try:
                # Read the encrypted file
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # Decrypt the data
                security_manager = SecurityManager()
                try:
                    container = json.loads(base64.b64decode(encrypted_data).decode())
                    encrypted_data = base64.b64decode(container['data'].encode())
                    
                    # Try to decrypt with the provided password
                    # Create a key from the password
                    key = hashlib.sha256(password.encode()).digest()
                    key = base64.urlsafe_b64encode(key)
                    
                    try:
                        # First try with the provided password
                        cipher = Fernet(key)
                        decrypted_data = cipher.decrypt(encrypted_data)
                        logging.info("Decryption with provided password successful")
                    except Exception as e:
                        logging.warning(f"Password decryption failed: {str(e)}")
                        # Try with container key if available
                        if 'key' in container:
                            try:
                                container_key = container['key'].encode() if isinstance(container['key'], str) else container['key']
                                cipher = Fernet(container_key)
                                decrypted_data = cipher.decrypt(encrypted_data)
                                logging.info("Decryption with container key successful")
                            except Exception as e:
                                logging.error(f"Container key decryption failed: {str(e)}")
                                flash('Decryption failed. Please try again.', 'error')
                                return redirect(url_for('shared_files'))
                        else:
                            flash('Decryption failed. Please try again.', 'error')
                            return redirect(url_for('shared_files'))
                except Exception as e:
                    logging.error(f"Error processing container: {str(e)}")
                    flash(f'Error decrypting file: invalid format or corrupted file.', 'error')
                    return redirect(url_for('shared_files'))
                
                # Create temp directory if it doesn't exist
                temp_dir = os.path.join('temp')
                os.makedirs(temp_dir, exist_ok=True)
                
                # Create a unique filename for the decrypted file
                temp_path = os.path.join(temp_dir, f"{file_id}_{int(time.time())}.{file_type}")
                
                # Save decrypted data to temp file
                with open(temp_path, 'wb') as f:
                    f.write(decrypted_data)
                
                # If we have metadata in the container, try to use it
                if 'metadata' in container and isinstance(container['metadata'], dict):
                    metadata = container['metadata']
                    # Use original filename from metadata if available
                    if 'original_filename' in metadata:
                        original_filename = metadata['original_filename']
                    # Use mime type from metadata if available
                    if 'mime_type' in metadata:
                        mime_type = metadata['mime_type']
                    # Use file type from metadata if available
                    if 'file_type' in metadata:
                        file_type = metadata['file_type']
                
                # Store download info in session
                session['pending_download'] = {
                    'path': temp_path,
                    'filename': original_filename or filename,
                    'mime_type': mime_type or 'application/octet-stream'
                }
                
                # Log successful decryption
                logging.info(f"User {user_context['username']} successfully decrypted shared file {file_id}")
                
                success = True
                
                # Redirect to download route
                return redirect(url_for('download_decrypted'))
                
            except Exception as e:
                logging.error(f"Error decrypting shared file: {str(e)}")
                import traceback
                logging.error(traceback.format_exc())
                flash(f'Error decrypting file: {str(e)}', 'error')
    
    except Exception as e:
        logging.error(f"Error in decrypt_shared_file: {str(e)}")
        flash('An error occurred while decrypting the file.', 'error')
    
    return redirect(url_for('shared_files'))

@app.route('/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
        
    try:
        # Attempt to delete the file
        success, message = file_manager.delete_file(file_id, user_context)
        flash(message, 'success' if success else 'error')
    except Exception as e:
        logging.error(f"Error deleting file: {str(e)}")
        flash(f"Error deleting file: {str(e)}", 'error')
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('temp', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    
    # Open browser only if not already opened
    if not os.environ.get('BROWSER_OPENED'):
        os.environ['BROWSER_OPENED'] = '1'
        webbrowser.open('http://127.0.0.1:5000')
    
    # Run the app
    app.run(debug=True)
