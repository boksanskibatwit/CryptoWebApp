from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from nacl.public import PublicKey, PrivateKey, SealedBox
from nacl.encoding import Base64Encoder
from nacl.exceptions import CryptoError
import sqlite3
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import uuid
import os

# Initialize SQLite database
def init_db():
    db_path = "data.db"

    # Optional: delete database if needed
    # if os.path.exists(db_path):
    #     os.remove(db_path)

    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS public_keys (
            username TEXT PRIMARY KEY,
            pubkey TEXT NOT NULL
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            ciphertext TEXT NOT NULL
        )""")
        conn.commit()

    print("[DB INIT] Tables created (if they didn’t already exist).")

init_db()

# Initialize the Flask app
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for frontend JS requests

# Argon2 password hasher for secure password storage
ph = PasswordHasher()

# ------------------ Routes ------------------ #

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    
    try:
        with sqlite3.connect("data.db") as conn:
            c = conn.cursor()
            c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if c.fetchone():
                return jsonify({'error': 'Username already exists'}), 400
            
            # Hash the password using Argon2
            password_hash = ph.hash(password)

            # Insert new user into the database
            c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            conn.commit()
            return jsonify({'status': 'User registered successfully'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
    password = data.get('password')


    try:
        with sqlite3.connect("data.db") as conn:
            c = conn.cursor()
            c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            if not row:
                return jsonify({'error': 'Invalid credentials'}), 401
            
            stored_hash = row[0]
            if not ph.verify(stored_hash, password):
                return jsonify({'error': 'Invalid credentials'}), 401
            
            stored_hash = row[0]
            ph.verify(stored_hash, password)
            return jsonify({'status': 'Login successful'}), 200
    except VerifyMismatchError:
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Upload a user's public key after login
@app.route('/upload_key', methods=['POST'])
def upload_key():
    data = request.json
    username = data.get('username')
    pubkey = data.get('public_key')

    try:
        #Validating the public key using PyNaCl
        _=PublicKey(pubkey, encoder=Base64Encoder)

        with sqlite3.connect("data.db") as conn:
            c = conn.cursor()
            c.execute("REPLACE INTO public_keys (username, pubkey) VALUES (?, ?)", (username, pubkey))
            conn.commit()
            return jsonify({'status': 'Public key uploaded successfully'}), 200
    except Exception:
        return jsonify({'error': 'Invalid public key format'}), 400


# Retrieve public key for a specific user (used for encrypting messages)
@app.route('/get_key/<username>', methods=['GET'])
def get_key(username):
    try:
        with sqlite3.connect("data.db") as conn:
            c = conn.cursor()
            c.execute("SELECT pubkey FROM public_keys WHERE username = ?", (username,))
            row = c.fetchone()
            if not row:
                return jsonify({'error': 'Public key not found'}), 404
            return jsonify({'public_key': row[0]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Store an encrypted message for a recipient
@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    sender = data.get('sender')
    recipient = data.get('recipient')
    ciphertext = data.get('ciphertext')
    msg_id = str(uuid.uuid4())

    if not(sender and recipient and ciphertext):
        return jsonify({'error': 'Missing sender, recipient, or ciphertext'}), 400
    
    try:
        with sqlite3.connect("data.db") as conn:
            c = conn.cursor()
            c.execute("""INSERT INTO messages (id, sender, recipient, ciphertext) Values (?, ?, ?, ?)""",
                       (msg_id, sender, recipient, ciphertext))
            conn.commit()
        return jsonify({'status': 'Message stored successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Retrieve and delete all stored messages for a user
@app.route('/get_messages/<username>', methods=['GET'])
def get_messages(username):
    try:
        with sqlite3.connect("data.db") as conn:
            c = conn.cursor()
            c.execute("SELECT id, sender, ciphertext FROM messages WHERE recipient = ?", (username,))
            rows = c.fetchall()

            #Delete messages after reading
            #c.execute("DELETE FROM messages WHERE recipient = ?", (username,))
            #conn.commit()

        messages = [{'id': row[0], 'from': row[1], 'ciphertext': row[2]} for row in rows]
        return jsonify({'messages': messages}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Serve the frontend web interface
@app.route('/')
def index():
    return render_template('index.html')


# Run the Flask development server
if __name__ == '__main__':
    app.run(debug=True)
