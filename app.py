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
from datetime import datetime
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
            cursor = conn.execute(
                "SELECT filename, file_path FROM files WHERE id = ? AND owner_id = ?",
                (file_id, user_context['user_id'])
            )
            file_info = cursor.fetchone()
            
            if not file_info:
                flash('File not found or access denied.', 'error')
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
            cursor = conn.execute(
                "SELECT filename, file_path FROM files WHERE id = ?",
                (file_id,)
            )
            file_info = cursor.fetchone()
            if not file_info:
                flash('File information not found.', 'error')
                return redirect(url_for('dashboard'))
            
            filename, file_path = file_info
            logging.info(f"Starting decryption for file: {filename} (ID: {file_id}, Path: {file_path})")
            
            # Check if file exists
            if not os.path.exists(file_path):
                flash(f'File not found on disk: {file_path}', 'error')
                return redirect(url_for('dashboard'))
            
            # Log file size for debugging
            file_size = os.path.getsize(file_path)
            logging.info(f"Encrypted file size: {file_size} bytes")

        # Call the file manager's decrypt method
        success, message, decrypted_data = file_manager.decrypt_file(file_id, user_context)
        
        if not success or not decrypted_data:
            logging.error(f"Decryption failed: {message}")
            flash(message, 'error')
            return redirect(url_for('dashboard'))
        
        # Clean up filename for the decrypted version
        clean_filename = filename
        if clean_filename.startswith("encrypted_"):
            clean_filename = clean_filename[10:]
        
        # Determine the correct mimetype based on file extension
        mime_type = 'application/octet-stream'  # Default mimetype
        file_ext = os.path.splitext(clean_filename)[1].lower()
        
        # Log file extension
        logging.info(f"File extension: {file_ext}")
        
        # Common image formats
        if file_ext in ['.jpg', '.jpeg']:
            mime_type = 'image/jpeg'
        elif file_ext == '.png':
            mime_type = 'image/png'
        elif file_ext == '.gif':
            mime_type = 'image/gif'
        elif file_ext == '.bmp':
            mime_type = 'image/bmp'
        elif file_ext == '.tiff' or file_ext == '.tif':
            mime_type = 'image/tiff'
        # Document formats
        elif file_ext == '.pdf':
            mime_type = 'application/pdf'
        elif file_ext == '.doc' or file_ext == '.docx':
            mime_type = 'application/msword'
        elif file_ext == '.xls' or file_ext == '.xlsx':
            mime_type = 'application/vnd.ms-excel'
        
        logging.info(f"Decryption successful for file: {filename}, type: {mime_type}, size: {len(decrypted_data)} bytes")
        
        # Check the first few bytes of the decrypted data for debugging
        header_bytes = decrypted_data[:20].hex() if decrypted_data else "No data"
        logging.info(f"Decrypted data header: {header_bytes}")
        
        # Return the decrypted file to the user with the correct mimetype
        response = send_file(
            io.BytesIO(decrypted_data),
            mimetype=mime_type,
            as_attachment=True,
            download_name=f"decrypted_{clean_filename}"
        )
        
        # Set additional headers to improve browser handling
        response.headers['Content-Disposition'] = f'attachment; filename="decrypted_{clean_filename}"'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        return response
            
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logging.error(f"Decryption error: {str(e)}")
        logging.error(f"Traceback: {error_details}")
        flash(f'Error decrypting file: {str(e)}', 'error')
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

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('temp', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    
    # Generate responsive CSS if it doesn't exist
    css_path = 'static/css/responsive.css'
    if not os.path.exists(css_path):
        with open(css_path, 'w') as f:
            f.write("""
            @media (max-width: 768px) {
                .container { padding: 10px; }
                .card { margin: 10px 0; }
                .btn { width: 100%; margin: 5px 0; }
                table { font-size: 12px; }
                th, td { padding: 5px; }
            }
            """)
    
    # Open browser only if not already opened
    if not os.environ.get('BROWSER_OPENED'):
        os.environ['BROWSER_OPENED'] = '1'
        webbrowser.open('http://127.0.0.1:5000')
    
    # Run the app
    app.run(debug=True)