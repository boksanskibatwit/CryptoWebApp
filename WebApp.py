from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid

app = Flask(__name__)
CORS(app)  # allow cross-origin requests from the frontend

# In-memory storage (for simplicity; replace with a database for production)
users = {}
public_keys = {}
messages = {}

# ------------------ Routes ------------------ #

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password_hash = data.get('password_hash')

    if username in users:
        return jsonify({'error': 'Username already exists'}), 400

    users[username] = {'password_hash': password_hash}
    return jsonify({'status': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password_hash = data.get('password_hash')

    user = users.get(username)
    if not user or user['password_hash'] != password_hash:
        return jsonify({'error': 'Invalid credentials'}), 401

    return jsonify({'status': 'Login successful'}), 200


@app.route('/upload_key', methods=['POST'])
def upload_key():
    data = request.json
    username = data.get('username')
    pubkey = data.get('public_key')

    public_keys[username] = pubkey
    return jsonify({'status': 'Key uploaded'}), 200


@app.route('/get_key/<username>', methods=['GET'])
def get_key(username):
    key = public_keys.get(username)
    if not key:
        return jsonify({'error': 'Key not found'}), 404
    return jsonify({'public_key': key}), 200


@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    sender = data.get('sender')
    recipient = data.get('recipient')
    ciphertext = data.get('ciphertext')

    msg_id = str(uuid.uuid4())
    messages.setdefault(recipient, []).append({
        'id': msg_id,
        'from': sender,
        'ciphertext': ciphertext
    })
    return jsonify({'status': 'Message stored'}), 200


@app.route('/get_messages/<username>', methods=['GET'])
def get_messages(username):
    user_messages = messages.pop(username, [])
    return jsonify({'messages': user_messages}), 200


if __name__ == '__main__':
    app.run(debug=True)
