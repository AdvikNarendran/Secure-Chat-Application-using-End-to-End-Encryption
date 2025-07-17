import os
import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, g
import jwt

from auth import blacklisted_tokens  # Assumes this exists

JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
ALGORITHM = "HS256"

key_bp = Blueprint("key", __name__)

def jwt_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"error": "Missing or malformed Authorization header"}), 401

        token = parts[1]
        if token in blacklisted_tokens:
            return jsonify({"error": "Token has been revoked"}), 401

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
            g.current_user = payload["sub"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return wrapped


@key_bp.route("/register", methods=["POST"])
@jwt_required
def register_key():
    data = request.get_json() or {}
    rsa_pub = data.get("publicKey")
    ecdh_pub = data.get("ecdhPublicKey")
    sign_pub = data.get("signPublicKey")  # Optional signing public key

    if not rsa_pub or not ecdh_pub:
        return jsonify({"error": "Missing publicKey or ecdhPublicKey"}), 400

    update_doc = {
        "publicKey": rsa_pub,
        "ecdhPublicKey": ecdh_pub,
        "updated_at": datetime.datetime.utcnow()
    }

    if sign_pub:
        update_doc["signPublicKey"] = sign_pub

    keys_coll = g.db.keys
    keys_coll.update_one(
        {"username": g.current_user},
        {"$set": update_doc},
        upsert=True
    )
    return "", 204


@key_bp.route("/public/<username>", methods=["GET"])
@jwt_required
def get_public_key(username):
    rec = g.db.keys.find_one({"username": username})
    if not rec or "publicKey" not in rec or "ecdhPublicKey" not in rec:
        return jsonify({"error": "Public key not found"}), 404

    return jsonify({
        "publicKey": rec["publicKey"],
        "ecdhPublicKey": rec["ecdhPublicKey"]
    }), 200


@key_bp.route("/ecdh/<username>", methods=["GET"])
@jwt_required
def get_ecdh_pubkey(username):
    rec = g.db.keys.find_one({"username": username})
    if not rec or "ecdhPublicKey" not in rec:
        return jsonify({"error": "ECDH public key not found"}), 404

    return jsonify({
        "publicKey": rec["ecdhPublicKey"]
    }), 200


@key_bp.route("/public-sign/<username>", methods=["GET"])
@jwt_required
def get_sign_pubkey(username):
    rec = g.db.keys.find_one({"username": username})
    if not rec or "signPublicKey" not in rec:
        return jsonify({"error": "Signing key not found"}), 404

    return jsonify({
        "signPublicKey": rec["signPublicKey"]
    }), 200
