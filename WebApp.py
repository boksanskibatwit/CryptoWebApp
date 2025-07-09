from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import uuid

# Initialize the Flask app
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for frontend JS requests

# In-memory storage for users, public keys, and messages
# NOTE: This is temporary and resets when server restarts.
# Use a real database (e.g., SQLite, Redis) for persistence.
users = {}         # Format: { username: { password_hash: ... } }
public_keys = {}   # Format: { username: base64_public_key }
messages = {}      # Format: { recipient: [ { from, ciphertext, id }, ... ] }

# ------------------ Routes ------------------ #

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password_hash = data.get('password_hash')  # Should be Argon2 on frontend or server

    # Prevent duplicate usernames
    if username in users:
        return jsonify({'error': 'Username already exists'}), 400

    # Store user with password hash
    users[username] = {'password_hash': password_hash}
    return jsonify({'status': 'User registered successfully'}), 201


# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password_hash = data.get('password_hash')

    user = users.get(username)
    if not user or user['password_hash'] != password_hash:
        return jsonify({'error': 'Invalid credentials'}), 401

    return jsonify({'status': 'Login successful'}), 200


# Upload a user's public key after login
@app.route('/upload_key', methods=['POST'])
def upload_key():
    data = request.json
    username = data.get('username')
    pubkey = data.get('public_key')

    public_keys[username] = pubkey
    return jsonify({'status': 'Key uploaded'}), 200


# Retrieve public key for a specific user (used for encrypting messages)
@app.route('/get_key/<username>', methods=['GET'])
def get_key(username):
    key = public_keys.get(username)
    if not key:
        return jsonify({'error': 'Key not found'}), 404
    return jsonify({'public_key': key}), 200


# Store an encrypted message for a recipient
@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    sender = data.get('sender')
    recipient = data.get('recipient')
    ciphertext = data.get('ciphertext')

    # Generate a unique message ID
    msg_id = str(uuid.uuid4())

    # Store the message under the recipient's message queue
    messages.setdefault(recipient, []).append({
        'id': msg_id,
        'from': sender,
        'ciphertext': ciphertext
    })

    return jsonify({'status': 'Message stored'}), 200


# Retrieve and delete all stored messages for a user
@app.route('/get_messages/<username>', methods=['GET'])
def get_messages(username):
    # Pop messages for user (clears after reading)
    user_messages = messages.pop(username, [])
    return jsonify({'messages': user_messages}), 200


# Serve the frontend web interface
@app.route('/')
def index():
    return render_template('index.html')


# Run the Flask development server
if __name__ == '__main__':
    app.run(debug=True)
