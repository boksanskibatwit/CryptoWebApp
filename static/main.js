// Globals to track user state and keys
let currentUser = "";
let keyPair = null;       // User's own Curve25519 keypair
let sharedSecret = null;  // Not used yet (NaCl handles key agreement automatically)

// Hashing function for passwords (currently a placeholder)
function hashPassword(password) {
    // NOTE: Replace with Argon2 hashing on the backend for real security
    return btoa(password); // base64 encode for demo purposes
}

/**
 * Register a new user.
 * Sends username and password hash to backend /register endpoint.
 */
function register() {
    const username = document.getElementById('username').value;
    const password = hashPassword(document.getElementById('password').value);

    fetch('/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password_hash: password})
    }).then(r => r.json())
      .then(data => alert(JSON.stringify(data)));
}

/**
 * Login a user and upload their public key.
 * If login succeeds, generate Curve25519 keypair and upload public key to server.
 */
function login() {
    const username = document.getElementById('username').value;
    const password = hashPassword(document.getElementById('password').value);
    currentUser = username;

    fetch('/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password_hash: password})
    }).then(res => {
        if (res.ok) {
            // Generate keypair after successful login
            keyPair = nacl.box.keyPair();
            const publicKeyBase64 = nacl.util.encodeBase64(keyPair.publicKey);

            // Upload public key to server
            fetch('/upload_key', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, public_key: publicKeyBase64})
            });

            alert("Logged in and key uploaded");
        } else {
            alert("Login failed");
        }
    });
}

/**
 * Encrypt and send a message to a recipient.
 * 1. Fetch recipient's public key.
 * 2. Generate random nonce.
 * 3. Encrypt message using nacl.box.
 * 4. Send ciphertext and nonce to backend.
 */
function sendMessage() {
    const recipient = document.getElementById('recipient').value;
    const plaintext = document.getElementById('message').value;

    // Get recipient's public key
    fetch('/get_key/' + recipient)
        .then(r => r.json())
        .then(data => {
            const recipientPubKey = nacl.util.decodeBase64(data.public_key);

            // Generate a unique nonce (must never repeat!)
            const nonce = nacl.randomBytes(nacl.box.nonceLength);

            // Convert message to Uint8Array
            const messageUint8 = nacl.util.decodeUTF8(plaintext);

            // Encrypt the message
            const box = nacl.box(messageUint8, nonce, recipientPubKey, keyPair.secretKey);

            // Format: nonce + ciphertext (both base64 encoded)
            const payload = {
                sender: currentUser,
                recipient: recipient,
                ciphertext: nacl.util.encodeBase64(nonce) + "." + nacl.util.encodeBase64(box)
            };

            // Send to backend
            return fetch('/send_message', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
        }).then(() => {
            alert("Message sent!");
        });
}

/**
 * Fetch and decrypt any new messages for the current user.
 * 1. Get list of messages from server.
 * 2. For each message, fetch sender's public key.
 * 3. Decrypt using nacl.box.open.
 * 4. Display on screen.
 */
function getMessages() {
    fetch('/get_messages/' + currentUser)
        .then(r => r.json())
        .then(data => {
            const msgDiv = document.getElementById('messages');
            msgDiv.innerHTML = ""; // Clear old messages

            data.messages.forEach(msg => {
                // Split the message into nonce and ciphertext
                const parts = msg.ciphertext.split(".");
                const nonce = nacl.util.decodeBase64(parts[0]);
                const box = nacl.util.decodeBase64(parts[1]);

                // Get sender's public key to decrypt
                fetch('/get_key/' + msg.from)
                    .then(r => r.json())
                    .then(senderKey => {
                        const senderPubKey = nacl.util.decodeBase64(senderKey.public_key);

                        // Attempt to decrypt
                        const decrypted = nacl.box.open(box, nonce, senderPubKey, keyPair.secretKey);

                        if (decrypted) {
                            const text = nacl.util.encodeUTF8(decrypted);
                            msgDiv.innerHTML += `<p><b>${msg.from}:</b> ${text}</p>`;
                        } else {
                            msgDiv.innerHTML += `<p><b>${msg.from}:</b> <i>Unable to decrypt</i></p>`;
                        }
                    });
            });
        });
}
