# Secure File Manager 2.0

A secure web application for encrypted file storage and sharing with enhanced authentication features including OTP-based account recovery.

## Core Features

- 🔒 User authentication with secure password hashing
- 📱 Two-factor authentication for account recovery via SMS
- 🔐 AES-256 encryption for all stored files
- 🔄 File sharing with permission management
- 📱 Mobile-responsive design
- 🕒 Time-limited access controls for shared files
- 🔍 Comprehensive audit logging for security monitoring
- 🛡️ Multiple encryption levels (standard and high-security options)
- 📝 File integrity verification through hash comparison
- 🌐 Modern UI with glassmorphism design elements

## Setup and Installation

1. Clone the repository
   ```
   git clone https://github.com/Princekumar8271/2.0-Secure-file-encryption.git
   cd 2.0-Secure-file-encryption
   ```

2. Install dependencies
   ```
   pip install -r requirements.txt
   ```

3. Configure environment variables (required for Twilio SMS)
   ```
   # Create a .env file with the following variables
   TWILIO_ACCOUNT_SID=your_account_sid
   TWILIO_AUTH_TOKEN=your_auth_token
   TWILIO_PHONE_NUMBER=your_twilio_phone
   ```

4. Configure SMS delivery (optional but recommended)
   ```
   python configure_sms.py
   ```

5. Run the application
   ```
   python app.py
   ```

## SMS Verification Options

The system uses SMS for OTP (One-Time Password) verification during password recovery:

1. **Development Mode**: OTP codes are printed to the console
2. **Direct SMS Mode**: OTP codes are saved to files for easy testing
3. **Twilio API**: For production use with real SMS delivery

## Security Features

- **AES-256 encryption** for all stored files
- **Tiered encryption levels** offering standard and high-security options
- **Secure password hashing** with unique salts for each user
- **JWT token-based authentication** with expiration controls
- **CSRF protection** on all forms to prevent cross-site request forgery
- **OTP verification** for account recovery
- **Automatic detection of Indian phone numbers** for proper formatting
- **Container-based encryption** that packages encrypted data with metadata
- **File integrity verification** through SHA-256 hash comparison
- **Granular permission system** with read/write/admin levels

## Technology Stack

### Backend
- **Python Flask** (v2.2.3) for the web framework
- **SQLite** for the database
- **Flask-WTF** for form handling and CSRF protection
- **Cryptography** library for secure encryption operations
- **PyJWT** for JWT token generation and validation
- **Twilio API** integration for SMS delivery
- **Python-dotenv** for environment variable management

### Frontend
- **HTML5/CSS3** for structure and styling
- **Tailwind CSS** for responsive design and UI components
- **JavaScript** for interactivity and animations
- **Font Awesome** for iconography

### Security Infrastructure
- **CSRF Protection** via Flask-WTF to prevent cross-site request forgery attacks
- **Secure containers** for encrypted file storage that include metadata
- **Multi-layered encryption** for high-security files
- **Audit logging** for all sensitive operations

## Deployment

The application can be deployed to production using:

1. **Gunicorn** as the WSGI HTTP server
2. **Nginx** as a reverse proxy (recommended)
3. **Docker** for containerization (optional)

Procfile is included for easy deployment to platforms like Heroku.

## Application Structure

```
├── app.py                # Main application file
├── core/                 # Core modules
│   ├── auth.py           # Authentication manager
│   ├── security.py       # Encryption and security utilities
│   ├── file_manager.py   # File handling and storage
│   └── audit.py          # Audit logging
├── templates/            # HTML templates
├── static/               # Static assets (CSS, JS, images)
├── secure_storage/       # Encrypted file storage
├── sms_logs/             # SMS delivery logs (dev mode)
└── requirements.txt      # Project dependencies
```

## License

[MIT License](LICENSE) 