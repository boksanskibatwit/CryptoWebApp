let currentUser = "";
let keyPair = null;
let sharedSecret = null;

// Dummy password hash for now (should be Argon2-hashed on server ideally)
function hashPassword(password) {
    return btoa(password); // Just for demo purposes
}

function register() {
    const username = document.getElementById('username').value;
    const password = hashPassword(document.getElementById('password').value);

    fetch('/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password_hash: password})
    }).then(r => r.json()).then(data => alert(JSON.stringify(data)));
}

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
            // Generate keypair and upload public key
            keyPair = nacl.box.keyPair();
            const publicKeyBase64 = nacl.util.encodeBase64(keyPair.publicKey);

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

function sendMessage() {
    const recipient = document.getElementById('recipient').value;
    const plaintext = document.getElementById('message').value;

    fetch('/get_key/' + recipient)
        .then(r => r.json())
        .then(data => {
            const recipientPubKey = nacl.util.decodeBase64(data.public_key);

            // Compute shared secret
            const nonce = nacl.randomBytes(nacl.box.nonceLength);
            const messageUint8 = nacl.util.decodeUTF8(plaintext);

            const box = nacl.box(messageUint8, nonce, recipientPubKey, keyPair.secretKey);

            const payload = {
                sender: currentUser,
                recipient: recipient,
                ciphertext: nacl.util.encodeBase64(nonce) + "." + nacl.util.encodeBase64(box)
            };

            return fetch('/send_message', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
        }).then(() => {
            alert("Message sent!");
        });
}

function getMessages() {
    fetch('/get_messages/' + currentUser)
        .then(r => r.json())
        .then(data => {
            const msgDiv = document.getElementById('messages');
            msgDiv.innerHTML = "";

            data.messages.forEach(msg => {
                const parts = msg.ciphertext.split(".");
                const nonce = nacl.util.decodeBase64(parts[0]);
                const box = nacl.util.decodeBase64(parts[1]);

                fetch('/get_key/' + msg.from)
                    .then(r => r.json())
                    .then(senderKey => {
                        const senderPubKey = nacl.util.decodeBase64(senderKey.public_key);
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
