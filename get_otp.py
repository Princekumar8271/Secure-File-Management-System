#!/usr/bin/env python
"""
OTP Retrieval Tool for Secure File Manager
------------------------------------------
This script helps you retrieve the OTP code for a username from logs or simulated SMS.
"""

import os
import sys
import glob
import re

def get_latest_file(pattern):
    """Get the most recently modified file matching the pattern"""
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)

def extract_otp_from_log(username):
    """Try to find OTP from various possible sources"""
    otp = None
    sources_checked = []
    
    # Try to find in sms_logs directory first (direct SMS mode)
    sms_log_path = os.path.join('sms_logs', f'sms_{username}.txt')
    sources_checked.append(sms_log_path)
    
    if os.path.exists(sms_log_path):
        with open(sms_log_path, 'r') as f:
            content = f.read()
            otp_match = re.search(r'OTP: (\d+)', content)
            if otp_match:
                otp = otp_match.group(1)
                return otp, sms_log_path
    
    # Try to find in server console output if it was redirected to a file
    console_log = get_latest_file('flask_output*.log')
    if console_log:
        sources_checked.append(console_log)
        with open(console_log, 'r') as f:
            content = f.read()
            otp_match = re.search(r'OTP CODE FOR {}: (\d+)'.format(username), content)
            if otp_match:
                otp = otp_match.group(1)
                return otp, console_log
    
    # Try to find in auth.log
    auth_log = 'auth.log'
    sources_checked.append(auth_log)
    if os.path.exists(auth_log):
        with open(auth_log, 'r') as f:
            content = f.read()
            otp_match = re.search(r'Generated OTP (\d+) for user {}'.format(username), content)
            if otp_match:
                otp = otp_match.group(1)
                return otp, auth_log
    
    return None, ', '.join(sources_checked)

def main():
    print("=" * 60)
    print("OTP Retrieval Tool for Secure File Manager")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        username = input("\nEnter the username you're trying to get the OTP for: ").strip()
    else:
        username = sys.argv[1]
    
    print(f"\nSearching for OTP for user: {username}...\n")
    
    otp, source = extract_otp_from_log(username)
    
    if otp:
        print(f"Found OTP: {otp}")
        print(f"Source: {source}")
        
        print("\n" + "=" * 25)
        print(f"  OTP CODE: {otp}")
        print("=" * 25)
    else:
        print(f"No OTP found for username '{username}'.")
        print(f"Sources checked: {source}")
        print("\nPossible reasons:")
        print("1. You haven't requested an OTP yet")
        print("2. The logs have been cleared")
        print("3. The username might be incorrect")
        print("\nSuggestion: Try requesting a new OTP from the forgotten password page")
    
    return 0 if otp else 1

if __name__ == "__main__":
    sys.exit(main()) 