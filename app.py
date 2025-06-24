from flask import Flask, request, jsonify
import jwt
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = Flask(__name__)

# Secret keys for JWT
ACCESS_SECRET_KEY = 'access_secret_key_123456'
REFRESH_SECRET_KEY = 'refresh_secret_key_789101'

# Generate RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Dummy user data
USERS = {
    "user": {"password": "pass", "email": "user@example.com"}
}


def rsa_encrypt(plaintext: str) -> str:
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(ciphertext).decode()


def rsa_decrypt(ciphertext_b64: str) -> str | None:
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return plaintext.decode()
    except Exception:
        return None


def create_access_token(user_id):
    payload = {
        "sub": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
        "iss": "sso-auth-app"
    }
    token = jwt.encode(payload, ACCESS_SECRET_KEY, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode()
    return rsa_encrypt(token)


def create_refresh_token(user_id):
    payload = {
        "sub": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
        "iss": "sso-auth-app"
    }
    token = jwt.encode(payload, REFRESH_SECRET_KEY, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode()
    return rsa_encrypt(token)


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(username)
    refresh_token = create_refresh_token(username)

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token
    })


@app.route('/refresh', methods=['POST'])
def refresh():
    data = request.json
    encrypted_token = data.get("refresh_token")
    if not encrypted_token:
        return jsonify({"error": "No refresh token provided"}), 400

    decrypted = rsa_decrypt(encrypted_token)
    if not decrypted:
        return jsonify({"error": "Invalid encrypted token"}), 401

    try:
        payload = jwt.decode(decrypted, REFRESH_SECRET_KEY, algorithms=["HS256"])
        user_id = payload["sub"]
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 403

    new_access_token = create_access_token(user_id)
    return jsonify({"access_token": new_access_token})


@app.route('/verify', methods=['GET'])
def verify():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization header missing"}), 401

    encrypted_token = auth_header.split(" ")[1]
    decrypted = rsa_decrypt(encrypted_token)
    if not decrypted:
        return jsonify({"error": "Invalid encrypted token"}), 401

    try:
        payload = jwt.decode(decrypted, ACCESS_SECRET_KEY, algorithms=["HS256"])
        return jsonify({"user": payload["sub"], "status": "verified"})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 403


if __name__ == '__main__':
    app.run(debug=True, port=5000)

