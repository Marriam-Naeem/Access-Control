
from datetime import datetime, time
import flask
import random
import string
import socket
from flask_mail import Mail, Message

app = flask.Flask(__name__, template_folder='templates', static_folder='static')


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
    end_time = time(1, 0, 0)

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
            return flask.render_template('access_granted.html', resource=selected_resource)
        else:
            return flask.render_template('access_denied.html', resource=selected_resource)
    else:
        return flask.render_template('index.html', message='Authentication failed due to Incorrect OTP')


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
