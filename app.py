import os
import webbrowser
import sqlite3
import logging
import io
import json
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from core.auth import AuthenticationManager
from core.file_manager import SecureFileManager
from datetime import datetime, timedelta
from pathlib import Path

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Initialize managers
auth_manager = AuthenticationManager()
file_manager = SecureFileManager()

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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        success, token = auth_manager.login(username, password)
        if success:
            session['token'] = token
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials!', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')
        phone_number = request.form.get('phone_number')
        
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
            
        # Validate phone number
        if not phone_number:
            errors.append('Please enter a phone number')
        else:
            # Check if it's a valid phone number format
            if phone_number.startswith('+'):
                # With country code (should be at least 11 digits: +1 + 10 digits)
                if len(phone_number) < 11:
                    errors.append('International phone number is too short')
            else:
                # Without country code (assuming Indian 10-digit number or US 10-digit)
                if len(phone_number) != 10:
                    errors.append('Phone number should be 10 digits')
        
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
            flash('Registration successful! Please login.', 'success')
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
def dashboard():
    if 'token' not in session:
        return redirect(url_for('login'))
        
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
def shared_files():
    if 'token' not in session:
        return redirect(url_for('login'))
        
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
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

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
def decrypt_file(file_id):
    if 'token' not in session:
        return redirect(url_for('login'))
    
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    try:
        # Get file information first to log details
        with sqlite3.connect(file_manager.db_path) as conn:
            # First check if user is the owner
            cursor = conn.execute(
                "SELECT filename, file_path, owner_id FROM files WHERE id = ?",
                (file_id,)
            )
            file_info = cursor.fetchone()
            if not file_info:
                flash('File information not found.', 'error')
                # Redirect based on referer
                referer = request.referrer
                if referer and 'shared' in referer:
                    return redirect(url_for('shared_files'))
                return redirect(url_for('dashboard'))
            
            filename, file_path, owner_id = file_info
            logging.info(f"Starting decryption for file: {filename} (ID: {file_id}, Path: {file_path})")
            
            # Check if user has permission - either owner or shared access
            has_permission = False
            if owner_id == user_context['user_id']:
                has_permission = True
                logging.info(f"User is the owner, proceeding with decryption")
            else:
                # Check access_control for permission
                cursor = conn.execute("""
                    SELECT permission_level FROM access_control 
                    WHERE resource_id = ? AND user_id = ? AND 
                          (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
                """, (file_id, user_context['user_id']))
                
                permission = cursor.fetchone()
                if permission and permission[0] in ('read', 'write', 'admin'):
                    has_permission = True
                    logging.info(f"User has {permission[0]} permission, proceeding with decryption")
            
            if not has_permission:
                flash('You do not have permission to decrypt this file.', 'error')
                # Redirect based on referer
                referer = request.referrer
                if referer and 'shared' in referer:
                    return redirect(url_for('shared_files'))
                return redirect(url_for('dashboard'))
            
            # Check if file exists
            if not os.path.exists(file_path):
                flash(f'File not found on disk: {file_path}', 'error')
                # Redirect based on referer
                referer = request.referrer
                if referer and 'shared' in referer:
                    return redirect(url_for('shared_files'))
                return redirect(url_for('dashboard'))
            
            # Get file size for debugging
            file_size = os.path.getsize(file_path)
            logging.info(f"Encrypted file size: {file_size} bytes")

        # Call the file manager's decrypt method
        success, message, decrypted_data = file_manager.decrypt_file(file_id, user_context)
        
        if not success or not decrypted_data:
            logging.error(f"Decryption failed: {message}")
            flash(message, 'error')
            # Redirect based on referer
            referer = request.referrer
            if referer and 'shared' in referer:
                return redirect(url_for('shared_files'))
            return redirect(url_for('dashboard'))
        
        # Clean up filename for the decrypted version
        clean_filename = filename
        if clean_filename.startswith("encrypted_"):
            clean_filename = clean_filename[10:]
        
        # Determine the correct mimetype based on file extension
        mime_type = 'application/octet-stream'
        ext = os.path.splitext(clean_filename)[1].lower()
        
        # Map common extensions to MIME types
        mime_mapping = {
            '.pdf': 'application/pdf',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.txt': 'text/plain',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.ppt': 'application/vnd.ms-powerpoint',
            '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        }
        
        if ext in mime_mapping:
            mime_type = mime_mapping[ext]
        
        # Create a BytesIO object from the decrypted data
        data_io = io.BytesIO(decrypted_data)
        
        # Return the file as an attachment
        logging.info(f"Returning decrypted file: {clean_filename} ({len(decrypted_data)} bytes)")
        return send_file(
            data_io,
            mimetype=mime_type,
            as_attachment=True,
            download_name=clean_filename
        )
            
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logging.error(f"Decryption error: {str(e)}")
        logging.error(f"Traceback: {error_details}")
        flash(f'Error decrypting file: {str(e)}', 'error')
        # Redirect based on referer
        referer = request.referrer
        if referer and 'shared' in referer:
            return redirect(url_for('shared_files'))
        return redirect(url_for('dashboard'))

@app.route('/delete/<file_id>', methods=['POST'])
def delete_file(file_id):
    if 'token' not in session:
        return redirect(url_for('login'))
    
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    try:
        # Delete file logic here
        with sqlite3.connect(file_manager.db_path) as conn:
            cursor = conn.execute(
                "SELECT file_path FROM files WHERE id = ? AND owner_id = ?",
                (file_id, user_context['user_id'])
            )
            file_info = cursor.fetchone()
            
            if not file_info:
                flash('File not found or access denied.', 'error')
                return redirect(url_for('dashboard'))
                
            file_path = file_info[0]
            
            # Delete from filesystem
            if os.path.exists(file_path):
                os.remove(file_path)
                
            # Delete from database
            conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
            
            flash('File deleted successfully.', 'success')
            
    except Exception as e:
        logging.error(f"Delete error: {str(e)}")
        flash('Error deleting file.', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/share/<file_id>', methods=['GET', 'POST'])
def share_file(file_id):
    if 'token' not in session:
        return redirect(url_for('login'))
    
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    # Get file details for display
    try:
        with sqlite3.connect(file_manager.db_path) as conn:
            # First check if the access_control table exists, create if not
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
                "SELECT filename, owner_id FROM files WHERE id = ?",
                (file_id,)
            )
            file_info = cursor.fetchone()
            
            if not file_info:
                flash('File not found.', 'error')
                return redirect(url_for('dashboard'))
                
            filename, owner_id = file_info
            
            # Only allow sharing if user is the owner (permissions already checked in file_manager)
            if request.method == 'POST':
                target_username = request.form.get('username')
                permission_level = request.form.get('permission', 'read')
                expiry_days = request.form.get('expiry')
                
                if not target_username:
                    flash('Please select a user to share with.', 'error')
                    return redirect(url_for('share_file', file_id=file_id))
                
                # Convert expiry to integer if provided
                if expiry_days and expiry_days.isdigit():
                    expiry_days = int(expiry_days)
                else:
                    expiry_days = None
                
                # Validate permission level
                if permission_level not in ['read', 'write', 'admin']:
                    permission_level = 'read'  # Default to read if invalid
                
                # Share the file
                success, message = file_manager.share_file(
                    file_id, 
                    user_context, 
                    target_username, 
                    permission_level,
                    expiry_days
                )
                
                flash(message, 'success' if success else 'error')
                if success:
                    return redirect(url_for('share_file', file_id=file_id))
            
            # Get list of users who have access to this file
            try:
                cursor = conn.execute("""
                    SELECT u.username, ac.permission_level, ac.granted_at, ac.expires_at 
                    FROM access_control ac 
                    JOIN users u ON ac.user_id = u.id 
                    WHERE ac.resource_id = ?
                """, (file_id,))
                
                shared_users = [
                    {
                        'username': row[0],
                        'permission': row[1],
                        'granted_at': datetime.fromisoformat(row[2]).strftime('%Y-%m-%d') if row[2] else '',
                        'expires_at': datetime.fromisoformat(row[3]).strftime('%Y-%m-%d') if row[3] else 'Never'
                    }
                    for row in cursor.fetchall()
                ]
            except sqlite3.Error as db_error:
                logging.error(f"Database error fetching shared users: {str(db_error)}")
                shared_users = []
            
            # Get all users for sharing (excluding current user)
            try:
                cursor = conn.execute(
                    "SELECT username FROM users WHERE id != ?",
                    (user_context['user_id'],)
                )
                available_users = [row[0] for row in cursor.fetchall()]
            except sqlite3.Error:
                # If there's an error, provide a minimal list 
                available_users = []
                flash('Could not load user list. Some functionality may be limited.', 'warning')
            
            return render_template(
                'share.html', 
                filename=filename, 
                file_id=file_id,
                shared_users=shared_users,
                available_users=available_users
            )
            
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logging.error(f"Share error: {str(e)}")
        logging.error(f"Traceback: {error_details}")
        flash(f'Error processing share request: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/explanation')
def explanation():
    return render_template('explanation.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle forgot password requests"""
    if request.method == 'POST':
        username = request.form.get('username')
        
        if not username:
            flash('Please enter your username.', 'error')
            return render_template('forgot_password.html')
            
        # Generate and send OTP
        success, message = auth_manager.generate_otp(username)
        
        if success:
            flash(message, 'success')
            # Redirect to OTP verification page
            return redirect(url_for('verify_otp', username=username))
        else:
            flash(message, 'error')
            return render_template('forgot_password.html')
            
    return render_template('forgot_password.html')

@app.route('/verify-otp/<username>', methods=['GET', 'POST'])
def verify_otp(username):
    """Verify OTP for password recovery"""
    if request.method == 'POST':
        otp = request.form.get('otp')
        
        if not otp:
            flash('Please enter the verification code.', 'error')
            return render_template('verify_otp.html', username=username)
            
        # Verify OTP
        success, message = auth_manager.verify_otp(username, otp)
        
        if success:
            flash('OTP verified successfully!', 'success')
            # Redirect to password reset page
            return redirect(url_for('reset_password', username=username))
        else:
            flash(message, 'error')
            return render_template('verify_otp.html', username=username)
            
    return render_template('verify_otp.html', username=username)

@app.route('/reset-password/<username>', methods=['GET', 'POST'])
def reset_password(username):
    """Reset password after OTP verification"""
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or not confirm_password:
            flash('Please enter both password fields.', 'error')
            return render_template('reset_password.html', username=username)
            
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', username=username)
            
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('reset_password.html', username=username)
            
        # Reset password
        success, message = auth_manager.reset_password(username, password)
        
        if success:
            flash('Password reset successful! Please login with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
            return render_template('reset_password.html', username=username)
            
    return render_template('reset_password.html', username=username)

@app.route('/user/profile')
def user_profile():
    if 'token' not in session:
        return redirect(url_for('login'))
        
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
        
    try:
        with sqlite3.connect(auth_manager.db_path) as conn:
            cursor = conn.execute(
                "SELECT username, role, phone_number, created_at, last_login FROM users WHERE id = ?",
                (user_context['user_id'],)
            )
            user_info = cursor.fetchone()
            
            if not user_info:
                flash('User profile not found', 'error')
                return redirect(url_for('dashboard'))
                
            # Get file statistics
            cursor = conn.execute(
                """
                SELECT 
                    COUNT(*) as total_files,
                    SUM(CASE WHEN encrypted = 1 THEN 1 ELSE 0 END) as encrypted_files,
                    SUM(CASE WHEN id IN (SELECT resource_id FROM access_control) THEN 1 ELSE 0 END) as shared_files
                FROM files 
                WHERE owner_id = ?
                """,
                (user_context['user_id'],)
            )
            stats = cursor.fetchone()
            
            profile = {
                'username': user_info[0],
                'role': user_info[1],
                'phone_number': user_info[2],
                'created_at': datetime.fromisoformat(user_info[3]).strftime('%Y-%m-%d %H:%M') if user_info[3] else 'Unknown',
                'last_login': datetime.fromisoformat(user_info[4]).strftime('%Y-%m-%d %H:%M') if user_info[4] else 'Never',
                'file_count': stats[0] or 0,
                'encrypted_count': stats[1] or 0,
                'shared_count': stats[2] or 0
            }
    except sqlite3.Error as e:
        logging.error(f"Database error in user profile: {str(e)}")
        flash(f'Database error: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
        
    return render_template('user_profile.html', profile=profile)

@app.route('/user/activity')
def activity_log():
    if 'token' not in session:
        return redirect(url_for('login'))
        
    user_context = auth_manager.security.verify_token(session['token'])
    if not user_context:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
        
    try:
        with sqlite3.connect(auth_manager.db_path) as conn:
            # Get activity log
            cursor = conn.execute(
                """
                SELECT action, resource_id, timestamp, status, additional_data 
                FROM audit_logs 
                WHERE user_id = ? 
                ORDER BY timestamp DESC 
                LIMIT 50
                """,
                (user_context['user_id'],)
            )
            activities = cursor.fetchall()
            
            activity_log = [
                {
                    'action': row[0],
                    'resource_id': row[1],
                    'timestamp': datetime.fromisoformat(row[2]).strftime('%Y-%m-%d %H:%M'),
                    'status': row[3],
                    'details': json.loads(row[4]) if row[4] else {}
                }
                for row in activities
            ]
            
    except sqlite3.Error as e:
        logging.error(f"Database error in activity log: {str(e)}")
        flash(f'Database error: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
        
    return render_template('activity_log.html', activities=activity_log)

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