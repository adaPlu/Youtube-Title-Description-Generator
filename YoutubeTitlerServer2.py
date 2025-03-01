# By Ada Pluguez
# 4/1/24
# YouTube Title/Description Generator Server Application
from flask import Flask, request, jsonify
import os
import hashlib
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import secrets
import logging
import uuid 
import psycopg2
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app
import logging
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.exc import IntegrityError

# PreAppLication Functions Required for intializatonof database.
# Function to create a schema if it does not exist
def create_schema_if_not_exists(schema_name):
    from sqlalchemy import text
    with db.engine.begin() as connection:  # Use begin() to ensure commit
        connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema_name}"))

# Configure basic logger
logging.basicConfig(level=logging.INFO)
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)


# Initialize Flask application
app = Flask(__name__)

# Note: Using a single database to manage both users and registration keys.
# Database configuration from environment variables
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://user1:new@localhost/youtube_database')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# User model in SQLAlchemy - Table1
class User(db.Model):
    __table_args__ = {'schema': 'user_management'}
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.LargeBinary(32), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    reset = db.Column(db.Boolean, default=False, nullable=False)
    loggedin = db.Column(db.Boolean, default=False)  # Tracks login status

# RegistrationKey model for storing registration keys - Table2    
class RegistrationKey(db.Model):
    __table_args__ = {'schema': 'user_management'}
    id = db.Column(db.Integer, primary_key=True)
    regkey = db.Column(db.String(120), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False)


def check_and_generate_keys():
    # Check if there are any keys in the database
    if RegistrationKey.query.first() is None:
        # No keys found, generate them
        keys = generate_registration_keys(1000)
        logging.info(f"Generated {len(keys)} initial keys because none were found in the database.")
    else:
        logging.info("Registration keys are already present in the database.")

def generate_registration_keys(number_of_keys=1000):
    keys = []
    for _ in range(number_of_keys):
        while True:
            new_key = str(uuid.uuid4())
            existing_key = RegistrationKey.query.filter_by(regkey=new_key).first()
            if not existing_key:
                break
        key_instance = RegistrationKey(regkey=new_key, used=False)
        db.session.add(key_instance)
        keys.append(new_key)
    
    try:
        db.session.commit()
        logging.info(f"Generated {len(keys)} registration keys.")
    except IntegrityError:
        db.session.rollback()
        logging.error("Failed to generate unique registration keys.")
        return False, 'Error generating unique registration keys'
    
    return True, keys


# Initialize the application, database, and create tables
with app.app_context():
    create_schema_if_not_exists('user_management')
    db.drop_all()
    db.create_all()
    check_and_generate_keys() 

# Email configuration for Flask-Mail integration
mail = Mail(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')


# Retrieves the next unused key
@app.route('/get_unused_key', methods=['GET'])
def get_unused_key():
    # Query for the first unused registration key
    key = RegistrationKey.query.filter_by(used=False).first()
    if key:
        # Return the key
        return jsonify({'message': 'Key retrieved successfully', 'key': key.regkey}), 200
    else:
        return jsonify({'message': 'No unused keys available'}), 404

# API endpoint to generate new registration keys
@app.route('/generate_keys', methods=['POST'])
def api_generate_registration_keys():
    number_of_keys = request.json.get('count', 10)  # Default to 10 if not specified
    success, keys_or_message = generate_registration_keys(number_of_keys)
    if not success:
        return jsonify({'message': keys_or_message}), 500
    return jsonify({'message': 'Registration keys generated successfully', 'keys': keys_or_message}), 201

# API endpoint to list all registration keys with their usage status
@app.route('/list_all_keys', methods=['GET'])
def list_all_keys():
    keys = RegistrationKey.query.all()
    keys_output = [{'key': key.regkey, 'used': key.used} for key in keys]
    return jsonify(keys_output)

# API endpoint to list all unused registration keys
@app.route('/list_unused_keys', methods=['GET'])
def list_unused_keys():
    unused_keys = RegistrationKey.query.filter_by(used=False).all()
    keys_output = [key.regkey for key in unused_keys]
    return jsonify(keys_output)
  
# API endpoint to generate new registration keys
@app.route('/generate_keysEn', methods=['POST'])
def api_generate_registration_keysEn():
    number_of_keys = request.json.get('count', 10)  # Default to 10 if not specified
    success, keys_or_message = generate_registration_keysEn(number_of_keys)
    if not success:
        return jsonify({'message': keys_or_message}), 500
    return jsonify({'message': 'Registration keys generated successfully', 'keys': keys_or_message}), 201

# Hash password with optional salt
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed_password, salt

# User registration endpoint
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    regkey = data.get('regkey')

    # Check registration key validity
    key = RegistrationKey.query.filter_by(regkey=regkey, used=False).first()
    if not key:
        return jsonify({'message': 'Invalid or already used registration key'}), 400

    # Check for existing username
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    # Check for existing email
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400

    # Hash and salt password
    password_hash, salt = hash_password(password)

    # Create new user
    #new_user = User(username=username, email=email, password_hash=password_hash.hex(), salt=salt)
    new_user = User(username=username, email=email, password_hash=password, salt=salt)
    db.session.add(new_user)

    # Mark registration key as used
    key.used = True
    db.session.commit()

    return jsonify({'message': 'User successfully registered'}), 201

# Function to verify the password
def verify_password(stored_password, provided_password, salt):
    #password_hash = hash_password(provided_password, salt)[0]
    #return stored_password == password_hash
    return stored_password == provided_password
    
# User login endpoint
@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and verify_password(user.password_hash, password, user.salt):
        user.loggedin = True
        db.session.commit()
        return jsonify({'message': 'Login successful'}), 200
    return jsonify({'message': 'Invalid credentials'}), 401
    
@app.route('/list_all_users', methods=['GET'])
def list_all_users():
    # Fetch all users from the database
    users = User.query.all()
    user_data = [{'username': user.username, 'email': user.email, 'loggedin': user.loggedin} for user in users]
    return jsonify(user_data), 200

@app.route('/logout', methods=['POST'])
def logout_user():
    data = request.json
    username = data.get('username')
    user = User.query.filter_by(username=username, loggedin=True).first()
    if user:
        user.loggedin = False
        db.session.commit()
        return jsonify({'message': 'Logout successful'}), 200
    return jsonify({'message': 'User not found or not logged in'}), 404
 
# Function to generate password reset link
def generate_password_reset_link(email):
    token = secrets.token_urlsafe()
    return f"http://yourfrontend/reset?token={token}&email={email}"

# Password reset request endpoint
@app.route('/request_reset', methods=['POST'])
def request_password_reset():
    data = request.json
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Email not found'}), 404
    reset_link = generate_password_reset_link(email)
    user.reset = True
    db.session.commit()
    msg = Message("Password Reset Request", recipients=[email])
    msg.body = f"Please click the following link to reset your password: {reset_link}"
    mail.send(msg)
    return jsonify({'message': 'Password reset link sent'}), 200

# Password reset endpoint
@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    new_password = data.get('new_password')
    user = User.query.filter_by(email=email).first()
    if not user or not user.reset:
        return jsonify({'message': 'Invalid request or link'}), 400
    user.password_hash, user.salt = hash_password(new_password)
    user.reset = False
    db.session.commit()
    return jsonify({'message': 'Password has been reset successfully'}), 200


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
