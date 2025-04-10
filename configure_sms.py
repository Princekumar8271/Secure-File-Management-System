#!/usr/bin/env python
"""
SMS Configuration Tool for Secure File Manager
----------------------------------------------
This script helps you configure SMS delivery options for OTP verification.
"""

import os
import json
import sys

def main():
    print("=" * 60)
    print("SMS Configuration for Secure File Manager")
    print("=" * 60)
    
    print("\nChoose SMS delivery method:")
    print("1. Twilio API (requires Twilio account)")
    print("2. Direct Delivery (simulated SMS for testing)")
    
    choice = input("\nEnter your choice (1/2): ").strip()
    
    config = {}
    
    if choice == '1':
        # Twilio Configuration
        print("\n--- Twilio Configuration ---")
        print("You'll need your Twilio Account SID, Auth Token, and a Twilio phone number.")
        print("You can sign up at: https://www.twilio.com/try-twilio")
        
        config['sms_backend'] = 'twilio'
        config['account_sid'] = input("Enter your Twilio Account SID: ").strip()
        config['auth_token'] = input("Enter your Twilio Auth Token: ").strip()
        config['phone_number'] = input("Enter your Twilio Phone Number (with + and country code, e.g., +12345678901): ").strip()
        
    elif choice == '2':
        # Direct (Simulated) SMS Configuration
        print("\n--- Direct SMS Configuration ---")
        print("This mode simulates SMS delivery by writing to local files.")
        print("OTPs will be saved to the 'sms_logs' folder for testing purposes.")
        
        config['sms_backend'] = 'direct'
        
    else:
        print("Invalid choice. Please run the script again and select 1 or 2.")
        return 1
    
    # Save configuration
    with open('twilio_config.json', 'w') as f:
        json.dump(config, f, indent=4)
    
    print("\nConfiguration saved to twilio_config.json")
    
    if choice == '1':
        print("\nTo use Twilio with the application:")
        print("1. Make sure the twilio package is installed: pip install twilio")
        print("2. Restart the application to apply the settings")
    else:
        print("\nDirect SMS delivery configured. OTPs will be saved to the 'sms_logs' folder.")
        print("Restart the application to apply the settings.")
    
    # Create batch/script file to set environment variables
    if os.name == 'nt':  # Windows
        with open('set_sms_env.bat', 'w') as f:
            f.write('@echo off\n\n')
            if choice == '1':
                f.write(f'set SMS_BACKEND=twilio\n')
                f.write(f'set TWILIO_ACCOUNT_SID={config.get("account_sid", "")}\n')
                f.write(f'set TWILIO_AUTH_TOKEN={config.get("auth_token", "")}\n')
                f.write(f'set TWILIO_PHONE_NUMBER={config.get("phone_number", "")}\n')
            else:
                f.write(f'set SMS_BACKEND=direct\n')
            f.write('\necho SMS environment variables set successfully!\n')
        
        print("\nAlso created set_sms_env.bat for manual environment setup if needed.")
    else:  # Unix-like systems
        with open('set_sms_env.sh', 'w') as f:
            f.write('#!/bin/bash\n\n')
            if choice == '1':
                f.write(f'export SMS_BACKEND=twilio\n')
                f.write(f'export TWILIO_ACCOUNT_SID="{config.get("account_sid", "")}"\n')
                f.write(f'export TWILIO_AUTH_TOKEN="{config.get("auth_token", "")}"\n')
                f.write(f'export TWILIO_PHONE_NUMBER="{config.get("phone_number", "")}"\n')
            else:
                f.write(f'export SMS_BACKEND=direct\n')
            f.write('\necho SMS environment variables set successfully!\n')
        
        # Make the script executable
        os.chmod('set_sms_env.sh', 0o755)
        print("\nAlso created set_sms_env.sh for manual environment setup if needed.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 