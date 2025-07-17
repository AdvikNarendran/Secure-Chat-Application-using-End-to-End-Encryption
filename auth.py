import os
import datetime
from flask import Blueprint, request, jsonify, g
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

# Use an environment variable for the JWT secret in production
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
ALGORITHM = "HS256"

auth_bp = Blueprint("auth", __name__)

# In‑memory token blacklist (simple; replace with Redis or DB in prod)
blacklisted_tokens = set()


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user.
    Expects JSON payload: { "username": "...", "password": "..." }
    """
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    users_coll = g.db.users
    if users_coll.find_one({"username": username}):
        return jsonify({"error": "User already exists"}), 400

    users_coll.insert_one({
        "username": username,
        "password_hash": generate_password_hash(password),
        "created_at": datetime.datetime.utcnow()
    })

    return jsonify({"message": "User registered successfully"}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate a user and issue a JWT (1 hr expiry).
    Expects JSON payload: { "username": "...", "password": "..." }
    Returns JSON: { "token": "..." }
    """
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    users_coll = g.db.users
    user = users_coll.find_one({"username": username})
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Create JWT payload with 1 hr expiry
    payload = {
        "sub": username,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

    return jsonify({"token": token}), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """
    Blacklist the current JWT so it can no longer be used.
    Expects header: Authorization: Bearer <token>
    """
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return jsonify({"error": "Missing or malformed Authorization header"}), 401

    token = parts[1]
    # We don’t verify expiration here; we simply blacklist whatever valid or expired token
    blacklisted_tokens.add(token)
    return jsonify({"message": "Logged out"}), 204

