# Secure File Manager 2.0

A secure web application for encrypted file storage and sharing with enhanced authentication features including OTP-based account recovery.

## Features

- 🔒 User authentication with secure password hashing
- 📱 Two-factor authentication for account recovery via SMS
- 🔐 AES-256 encryption for all stored files
- 🔄 File sharing with permission management
- 📱 Mobile-responsive design

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

3. Configure SMS delivery (optional but recommended)
   ```
   python configure_sms.py
   ```

4. Run the application
   ```
   python app.py
   ```

## SMS Verification Options

The system uses SMS for OTP (One-Time Password) verification during password recovery:

1. **Development Mode**: OTP codes are printed to the console
2. **Direct SMS Mode**: OTP codes are saved to files for easy testing
3. **Twilio API**: For production use with real SMS delivery

## Security Features

- AES-256 encryption for all stored files
- Secure password hashing with unique salts
- JWT token-based authentication
- OTP verification for account recovery
- Automatic detection of Indian phone numbers

## Technology Stack

- Python Flask for the web framework
- SQLite for the database
- Cryptography library for secure encryption
- Twilio API integration for SMS delivery
- Responsive front-end with CSS animations

## License

[MIT License](LICENSE) 