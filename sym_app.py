from flask import Flask, request, jsonify
import jwt
import datetime
from cryptography.fernet import Fernet

app = Flask(__name__)

# Secret keys
ACCESS_SECRET_KEY = 'access_secret_key_123456'
REFRESH_SECRET_KEY = 'refresh_secret_key_789101'

# Encryption key (symmetric)
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

# Dummy user data
USERS = {
    "user": {"password": "pass", "email": "user@example.com"}
}


def create_access_token(user_id):
    payload = {
        "sub": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
        "iss": "sso-auth-app"
    }
    token = jwt.encode(payload, ACCESS_SECRET_KEY, algorithm='HS256')
    # Ensure string before encrypting
    if isinstance(token, bytes):
        token = token.decode()
    return cipher.encrypt(token.encode()).decode()


def create_refresh_token(user_id):
    payload = {
        "sub": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
        "iss": "sso-auth-app"
    }
    token = jwt.encode(payload, REFRESH_SECRET_KEY, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode()
    return cipher.encrypt(token.encode()).decode()


def decrypt_token(encrypted_token):
    try:
        return cipher.decrypt(encrypted_token.encode()).decode()
    except Exception as e:
        return None


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

    decrypted = decrypt_token(encrypted_token)
    if not decrypted:
        return jsonify({"error": "Invalid encrypted token"}), 401

    try:
        payload = jwt.decode(decrypted, REFRESH_SECRET_KEY, algorithms=["HS256"])
        user_id = payload["sub"]
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 403

    # Issue new access token
    new_access_token = create_access_token(user_id)
    return jsonify({"access_token": new_access_token})


@app.route('/verify', methods=['GET'])
def verify():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization header missing"}), 401

    encrypted_token = auth_header.split(" ")[1]
    decrypted = decrypt_token(encrypted_token)
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
