import os
import re
import uuid
import hashlib
import logging
from datetime import datetime, timedelta, UTC

from flask import Flask, request, jsonify, make_response
import jwt
from dotenv import load_dotenv
import html
import sqlite3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
# Use a secure randomly generated key stored in environment variables
# Never hardcode secrets in your application code
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', str(uuid.uuid4()))

# Database setup
def get_db_connection():
    conn = sqlite3.connect('database.db' if not app.config.get('TESTING', False) else app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    conn.execute('''
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    conn.commit()
    conn.close()

init_db()

# Secure password hashing function
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32)  # Generate a secure random salt
    # Use a strong hashing algorithm with appropriate key derivation
    key = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA-256 hash algorithm
        password.encode('utf-8'),  # Convert password to bytes
        salt,  # Provide the salt
        100000,  # 100,000 iterations of the algorithm
        dklen=128  # Get a 128-byte key
    )
    return salt + key

def verify_password(stored_password, provided_password):
    salt = stored_password[:32]  # The salt is the first 32 bytes
    stored_key = stored_password[32:]
    # Hash the provided password with the same salt
    new_key = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        salt,
        100000,
        dklen=128
    )
    # Compare the stored key with the new key
    return new_key == stored_key

# Input validation functions
def validate_username(username):
    """Validate username contains only valid characters and has proper length"""
    if not username or not isinstance(username, str):
        return False
    # Only allow alphanumeric characters and some specific characters
    pattern = re.compile(r'^[a-zA-Z0-9_.-]{3,30}$')
    return bool(pattern.match(username))

def validate_password(password):
    """
    Validate password strength:
    - At least 8 characters
    - Contains uppercase and lowercase letters
    - Contains at least one digit
    - Contains at least one special character
    """
    if not password or not isinstance(password, str) or len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):  # At least one uppercase
        return False
    if not re.search(r'[a-z]', password):  # At least one lowercase
        return False
    if not re.search(r'[0-9]', password):  # At least one digit
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):  # At least one special char
        return False
    return True

# JWT token generation and validation
def generate_token(username):
    # Set token expiration time
    expiration = datetime.now(UTC) + timedelta(hours=1)
    # Create payload
    payload = {
        'exp': expiration,
        'iat': datetime.now(UTC),
        'sub': username
    }
    # Create JWT token
    token = jwt.encode(
        payload,
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return token

# Authentication decorator
def token_required(f):
    def decorator(*args, **kwargs):
        token = None
        # Check if token is in headers
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Verify token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['sub']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    # Rename the function to the wrapped function's name
    decorator.__name__ = f.__name__
    return decorator

# API Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Input validation
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Missing required fields'}), 400
    
    username = data['username']
    password = data['password']
    
    # Validate username and password format
    if not validate_username(username):
        return jsonify({'message': 'Invalid username format. Username must be 3-30 characters and contain only letters, numbers, underscores, dots, or hyphens.'}), 400
    
    if not validate_password(password):
        return jsonify({'message': 'Password does not meet security requirements. Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.'}), 400
    
    conn = get_db_connection()
    try:
        # Check if username already exists
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            conn.close()
            return jsonify({'message': 'Username already exists'}), 409
        
        # Hash password and store user
        hashed_password = hash_password(password)
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                    (username, hashed_password))
        conn.commit()
        conn.close()
        
        # Generate token
        token = generate_token(username)
        
        # Create a response with the token
        response_data = {
            'message': 'User registered successfully',
            'token': token
        }
        
        return jsonify(response_data), 201
    
    except Exception as e:
        conn.close()
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'message': 'An error occurred during registration'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Input validation
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Missing required fields'}), 400
    
    username = data['username']
    password = data['password']
    
    conn = get_db_connection()
    try:
        # Retrieve user from database
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if not user:
            # Use a generic error message to prevent username enumeration
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # Verify password
        stored_password = user['password']
        if not verify_password(stored_password, password):
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # Generate token
        token = generate_token(username)
        
        # Create a response with the token
        response_data = {
            'message': 'Login successful',
            'token': token
        }
        
        return jsonify(response_data), 200
    
    except Exception as e:
        if not conn.closed:
            conn.close()
        logger.error(f"Login error: {str(e)}")
        return jsonify({'message': 'An error occurred during login'}), 500

@app.route('/notes', methods=['POST'])
@token_required
def create_note(current_user):
    data = request.get_json()
    
    # Input validation
    if not data or 'title' not in data or 'content' not in data:
        return jsonify({'message': 'Missing required fields'}), 400
    
    title = data['title']
    content = data['content']
    
    # Sanitize inputs to prevent XSS
    title = html.escape(title)
    content = html.escape(content)
    
    conn = get_db_connection()
    try:
        # Get user_id
        user = conn.execute('SELECT id FROM users WHERE username = ?', (current_user,)).fetchone()
        if not user:
            conn.close()
            return jsonify({'message': 'User not found'}), 404
        
        user_id = user['id']
        
        # Use parameterized query to prevent SQL injection
        conn.execute('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)', 
                    (user_id, title, content))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Note created successfully'}), 201
    
    except Exception as e:
        if not conn.closed:
            conn.close()
        logger.error(f"Note creation error: {str(e)}")
        return jsonify({'message': 'An error occurred while creating the note'}), 500

@app.route('/notes', methods=['GET'])
@token_required
def get_notes(current_user):
    conn = get_db_connection()
    try:
        # Get user_id
        user = conn.execute('SELECT id FROM users WHERE username = ?', (current_user,)).fetchone()
        if not user:
            conn.close()
            return jsonify({'message': 'User not found'}), 404
        
        user_id = user['id']
        
        # Use parameterized query to prevent SQL injection
        notes = conn.execute('SELECT id, title, content, created_at FROM notes WHERE user_id = ?', 
                            (user_id,)).fetchall()
        conn.close()
        
        # Convert notes to list of dictionaries
        notes_list = []
        for note in notes:
            notes_list.append({
                'id': note['id'],
                'title': note['title'],
                'content': note['content'],
                'created_at': note['created_at']
            })
        
        return jsonify({'notes': notes_list}), 200
    
    except Exception as e:
        if not conn.closed:
            conn.close()
        logger.error(f"Error retrieving notes: {str(e)}")
        return jsonify({'message': 'An error occurred while retrieving notes'}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'message': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_server_error(error):
    logger.error(f"Server error: {str(error)}")
    return jsonify({'message': 'Internal server error'}), 500

if __name__ == '__main__':
    # In production, use a proper WSGI server and set debug=False
    app.run(debug=False, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))