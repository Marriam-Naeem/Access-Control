
# class AccessControl:

#     def __init__(self):
#         self.access_list = {}
#         self.policy_engine = PolicyEngine()
#         self.threat_intelligence = ThreatIntelligence()

#     def add_user(self, attributes, location=""):
#         user_id = str(uuid.uuid4())
#         hostname = socket.gethostname()

# # Get the IP address of the local machine
#         ip_address = socket.gethostbyname(hostname)

#         print(f"The IP address of the computer is: {ip_address}")
#         self.access_list[user_id] = {"attributes": set(attributes), "mfa_enabled": False, "risk_level": 0, "location": location}

#     def enable_mfa(self, user_id):
#         if user_id in self.access_list:
#             self.access_list[user_id]["mfa_enabled"] = True

#     def disable_mfa(self, user_id):
#         if user_id in self.access_list:
#             self.access_list[user_id]["mfa_enabled"] = False

#     def authenticate_user(self, user_id, mfa_code):
#         stored_mfa_code = self.access_list[user_id].get("stored_mfa_code")
#         if stored_mfa_code and stored_mfa_code == mfa_code:
#             return True
#         return False

#     def generate_mfa_code(self, user_id):
#         mfa_code = secrets.token_hex(2)
#         self.access_list[user_id]["stored_mfa_code"] = mfa_code
#         return mfa_code

#     def assess_risk(self, user_id):
#         self.access_list[user_id]["risk_level"] = random.uniform(0, 1)

#     def remove_user(self, user_id):
#         if user_id in self.access_list:
#             del self.access_list[user_id]

#     def check_access(self, user_id, resource, action, user_location=""):
#         if user_id in self.access_list:
#             user_attributes = self.access_list[user_id]["attributes"]
#             resource_attributes = self._get_resource_attributes(resource)
#             if self.policy_engine.evaluate_policy(user_attributes, resource_attributes, action):
#                 if self.access_list[user_id]["mfa_enabled"]:
#                     mfa_code = input("Enter your MFA code: ")
#                     if self.authenticate_user(user_id, mfa_code):
#                         self.assess_risk(user_id)
#                         if self.access_list[user_id]["risk_level"] < 0.5:
#                             if self._check_location_access(user_location, self.access_list[user_id]["location"]):
#                                 if self.threat_intelligence.is_user_safe(user_id):
#                                     return True
#                                 else:
#                                     print(f"Access denied. User {user_id} is flagged as a potential threat.")
#                                     return False
#                             else:
#                                 print(f"Access denied. User's location ({user_location}) does not match the required location.")
#                                 return False
#                         else:
#                             print("Access denied due to high risk level.")
#                             return False
#                     else:
#                         print("MFA authentication failed.")
#                         return False
#                 else:
#                     if self._check_location_access(user_location, self.access_list[user_id]["location"]):
#                         if self.threat_intelligence.is_user_safe(user_id):
#                             return True
#                         else:
#                             print(f"Access denied. User {user_id} is flagged as a potential threat.")
#                             return False
#                     else:
#                         print(f"Access denied. User's location ({user_location}) does not match the required location.")
#                         return False
#         return False

#     def _get_resource_attributes(self, resource):
#         return set(["confidential", "read-only"])

#     def _check_location_access(self, user_location, required_location):
#         try:
#             user_ip = ipaddress.IPv4Address(user_location)
#             required_ip = ipaddress.IPv4Network(required_location, strict=False)
#             return user_ip in required_ip
#         except ipaddress.AddressValueError:
#             return False

# class PolicyEngine:
#     def evaluate_policy(self, user_attributes, resource_attributes, action):
#         if "employee" in user_attributes and self._is_within_working_hours():
#             return True
#         else:
#             return False
#     def _is_within_working_hours(self):
#         now = datetime.now().time()
#         return datetime.strptime("09:00:00", "%H:%M:%S").time() <= now <= datetime.strptime("17:00:00", "%H:%M:%S").time()

# class ThreatIntelligence:
#     def __init__(self):
#         self.threat_feed_url = "https://api.example.com/threat-feed"
#     def is_user_safe(self, user_id):
#         try:
#             response = requests.get(f"{self.threat_feed_url}/check-user/{user_id}")
#             return response.json().get("is_safe", False)
#         except requests.RequestException:
#             print("Error checking threat intelligence. Proceeding with caution.")
#             return True
# access_control = AccessControl()

# @app.route('/', methods=['GET', 'POST'])
# def main():
#     if flask.request.method == 'GET':
#         return flask.render_template('index.html')
#     elif flask.request.method == 'POST':
#         username = flask.request.form['Username']
#         password = flask.request.form['Password']
#         funded_amount_investor = flask.request.form['FundedAmountInvestor']

#         # Authenticate the user using AccessControl
#         user_id = authenticate_user(username, password, funded_amount_investor)

#         if user_id:
#             # User authentication successful, check access control
#             resource = "sensitive_document.txt"
#             action = ["read"]
#             user_location = "192.168.1.1"  # You can modify this based on the user input

#             if access_control.check_access(user_id, resource, action, user_location):
#                 return flask.render_template('result_Yes.html')
#             else:
#                 return flask.render_template('result_No.html')

#         # Authentication failed, redirect to an error page or handle accordingly
#         return "Authentication failed"

# def authenticate_user(username, password, funded_amount_investor):
#     # Implement your authentication logic here
#     # For simplicity, use a basic check; you should replace this with a more secure method
#     if username == '1' and password == 'password' and funded_amount_investor == '2':
#         # Generate a user ID and add the user to AccessControl
#         user_id = str(uuid.uuid4())
#         access_control.add_user(["employee", "manager"], "192.168.1.1")
#         return user_id

#     return None

# if __name__ == '__main__':
#     app.run(debug=True)
from datetime import datetime, time
import flask
import random
import string
import socket
from flask_mail import Mail, Message

app = flask.Flask(__name__, template_folder='templates')

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'pisces.zaiby03@gmail.com'  # Replace with your Gmail email
app.config['MAIL_PASSWORD'] = 'yhqq uoji swbj qfbq'  # Replace with your Gmail password

mail = Mail(app)
STORED_OTP = ''
EMAIL=''

def check_location_access():
    def get_first_two_octets(ip_address):
        return '.'.join(ip_address.split('.')[:2])
    hostname = socket.gethostname()
    host_ip_address = socket.gethostbyname(hostname)
    required_ip = "192.168.100.12"
    return get_first_two_octets(host_ip_address) == get_first_two_octets(required_ip)

def check_working_hours():
    now = datetime.now().time()
    start_time = time(9, 0, 0)
    end_time = time(7, 0, 0)

    return start_time <= now <= end_time
def get_user_role(email):
    users_info = get_attributes_dict()
    for user_info in users_info:
        if user_info['email'] == email:
            return user_info['Role']
    return None  # Return None if the email is not found

def grant_access(resource, email):
    if (check_location_access()) and (check_working_hours()):
        role = get_user_role(email)
        if role == 'Project_Manager' and resource == 'Project':
            return True
        elif role == 'Developer' and resource == 'Task':
            return True
        elif role == 'Developer' and resource == 'Bug':
            return True
        elif role == 'Developer' and resource == 'Project':
            return False
        elif role == 'Developer' and resource == 'Code':
            return True
        elif role == 'SQA_Engineer' and resource == 'Project':
            return False
        else:
            return False
    else:
        return False

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    msg = Message('Your OTP', sender='wemma7932@gmail.com', recipients=[email])
    msg.body = f'Your OTP is: {otp}'
    mail.send(msg)

def set_stored_otp(otp):
    global STORED_OTP
    STORED_OTP = otp

def get_stored_otp():
    return STORED_OTP

@app.route('/', methods=['GET', 'POST'])
def main():
    if flask.request.method == 'GET':
        return flask.render_template('index.html')
    elif flask.request.method == 'POST':
        email = flask.request.form['Email']
        global EMAIL
        EMAIL=email
        password = flask.request.form['Password']

        # Authenticate the user using AccessControl
        auth_result = authenticate_user(email, password)

        if auth_result:
            otp = generate_otp()
            set_stored_otp(otp)
            send_otp_email(email, otp)
            return flask.render_template('otp_input.html', email=email)
        else:
            return flask.render_template('index.html', message='Authentication failed. Please check your credentials.')

@app.route('/verify_otp', methods=['POST'])
@app.route('/verify_otp', methods=['POST'])
@app.route('/verify_otp_and_grant_access', methods=['POST'])
def verify_otp_and_grant_access():
    entered_otp = flask.request.form['otp']
    selected_resource = flask.request.form['resource']
    print(selected_resource)
    stored_otp = get_stored_otp()

    if entered_otp == stored_otp:
        # OTP verified, now check access
        if grant_access(selected_resource, EMAIL):
            return f'Access granted to {selected_resource}!'
        else:
            return f'Access denied to {selected_resource}. Please check your permissions.'
    else:
        return 'Invalid OTP. Please try again.'


def authenticate_user(email, password):
    users_info = get_attributes_dict()
    for user_info in users_info:
        if user_info['email'] == email and user_info['password'] == password:
            return True
    return False

def get_attributes_dict():
    users_info = [
        {
            'email': 'zanwaar.bese20seecs@seecs.edu.pk',
            'password': 'password',
            'username': 'zanwaarpassword',
            'MFA_Enabled': True,
            'IPv4': '39.58.249.103',
            'Role': 'Project_Manager',
            'OTP': ''
        },
        {
            'email': 'jbfjdhanwaar.bese20seecs@seecs.edu.pk',
            'password': 'password',
            'username': 'zanwaarpassword',
            'MFA_Enabled': True,
            'IPv4': '39.58.249.103',
            'Role': 'Project_Manager',
            'OTP': ''
        },
        {
            'email': 'skdjskanwaar.bese20seecs@seecs.edu.pk',
            'password': 'password',
            'username': 'zanwaarpassword',
            'MFA_Enabled': True,
            'IPv4': '39.58.249.103',
            'Role': 'Project_Manager',
            'OTP': ''
        },
        {
            'email': 'tanwaar.bese20seecs@seecs.edu.pk',
            'password': 'password',
            'username': 'zanwaarpassword',
            'MFA_Enabled': True,
            'IPv4': '39.58.249.103',
            'Role': 'Developer',
            'OTP': ''
        },
        {
            'email': 'sanwaar.bese20seecs@seecs.edu.pk',
            'password': 'password',
            'username': 'sanwaarpassword',
            'MFA_Enabled': True,
            'IPv4': '39.58.249.103',
            'Role': 'Developer',
            'OTP': ''
        }
    ]
    return users_info

if __name__ == '__main__':
    app.run(debug=True)
