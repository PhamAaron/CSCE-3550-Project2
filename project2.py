# Requires pip installations of flask, cryptography, and pyJWT
# All of them will be listed in a file in the GitHub
# "pip install -r requirements.txt"

# This is a RESTful JWKS python server that provides public keys with unique identifiers for JSON (JWTs)

from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import time
import base64
import json
import jwt
import sqlite3

app = Flask(__name__)

# Global Variables
# Initialize an empty dictionary to store the keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
numbers = private_key.private_numbers()

# Initialize SQLite database
DB_FILE = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(DB_FILE)
c = conn.cursor()

# Create table if not exists
c.execute('''CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                exp INTEGER NOT NULL
             )''')
conn.commit()

# Serialize private key to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
private_pem_str = private_pem.decode('utf-8')

# Save private key to the database
c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_pem_str, int(time.time() + 3600)))
c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_pem_str, int(time.time() - 3600)))
conn.commit()

# Convert integer to base64    
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    
    return encoded.decode('utf-8')
    
# Endpoint for authentication and signed JWT
# All POST codes will be managed by the Flask implementation.
@app.route('/auth', methods=['POST'])
def auth():
    headers = {"kid": "goodKID"}
    token_payload = {
        "user": "username",
        "exp": time.time() + 3600
    }
    if 'expired' in request.args:
        headers["kid"] = "expiredKID"
        token_payload["exp"] = time.time() - 3600
    encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
    return encoded_jwt

# Endpoint to connect JWKS
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    keys = {
        "keys": [
            {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": "goodKID",
                "n": int_to_base64(numbers.public_numbers.n),
                "e": int_to_base64(numbers.public_numbers.e),
            }
        ]
    }
    return jsonify(keys)

# Main to run local host server 127.0.0.1 to port 8080 for gradebot
if __name__ == '__main__':
    app.run(port=8080, debug=True)