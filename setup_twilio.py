#!/usr/bin/env python
"""
Twilio Setup Script for Secure File Manager
------------------------------------------
This script helps set up environment variables for Twilio SMS integration.
"""

import os
import sys
import platform

def main():
    print("=" * 60)
    print("Twilio Setup for Secure File Manager")
    print("=" * 60)
    print("\nThis script will help you set up Twilio for sending SMS verification codes.")
    print("\nYou'll need to sign up for a Twilio account and get your Account SID,")
    print("Auth Token, and a Twilio phone number for sending SMS messages.")
    print("\nYou can sign up at: https://www.twilio.com/try-twilio")
    
    print("\nINDIAN PHONE NUMBER SUPPORT:")
    print("The system automatically detects 10-digit Indian phone numbers")
    print("and adds the +91 country code. No additional configuration needed.")
    
    # Get Twilio credentials
    account_sid = input("\nEnter your Twilio Account SID: ").strip()
    auth_token = input("Enter your Twilio Auth Token: ").strip()
    phone_number = input("Enter your Twilio Phone Number (with + and country code, e.g., +12345678901): ").strip()
    
    # Determine the appropriate file to modify based on OS
    if platform.system() == "Windows":
        # Windows - create a batch file
        set_cmd = "@echo off\n\n"
        set_cmd += f'set TWILIO_ACCOUNT_SID={account_sid}\n'
        set_cmd += f'set TWILIO_AUTH_TOKEN={auth_token}\n'
        set_cmd += f'set TWILIO_PHONE_NUMBER={phone_number}\n'
        set_cmd += "\necho Twilio environment variables set successfully!"
        
        with open("set_twilio_env.bat", "w") as f:
            f.write(set_cmd)
        
        print("\nCreated set_twilio_env.bat")
        print("Run this batch file before starting the application to set up Twilio.")
        
    else:
        # Unix-like systems (Linux, macOS) - create a shell script
        set_cmd = "#!/bin/bash\n\n"
        set_cmd += f'export TWILIO_ACCOUNT_SID="{account_sid}"\n'
        set_cmd += f'export TWILIO_AUTH_TOKEN="{auth_token}"\n'
        set_cmd += f'export TWILIO_PHONE_NUMBER="{phone_number}"\n'
        set_cmd += "\necho Twilio environment variables set successfully!"
        
        with open("set_twilio_env.sh", "w") as f:
            f.write(set_cmd)
        
        # Make the script executable
        os.chmod("set_twilio_env.sh", 0o755)
        
        print("\nCreated set_twilio_env.sh")
        print("Run 'source set_twilio_env.sh' before starting the application to set up Twilio.")
    
    print("\nTo use Twilio with the application, you'll need to:")
    print("1. Run the environment script before starting the application")
    print("2. Install the Twilio package with: pip install twilio")
    print("\nNOTE: In development mode, if Twilio is not configured, the OTP will be")
    print("printed to the console for testing purposes.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 