# auth_otp.py  (amendments only)

import datetime, random, string
from flask import Blueprint, request, jsonify, g, current_app
from flask_mail import Message
from werkzeug.security import generate_password_hash
from pymongo import ASCENDING, IndexModel

otp_bp = Blueprint('auth_otp', __name__)

def init_app(app):
    # … existing OTP TTL index setup …

    # ─── Reset‑OTP TTL index ───────────────────────────────────────────────
    # expireAfterSeconds applies to “created_at” field on reset tokens:
    app.db.resets.create_indexes([
        IndexModel([('username', ASCENDING)], unique=False),
        IndexModel([('created_at', ASCENDING)], expireAfterSeconds=app.config['RESET_TTL_SECONDS'])
    ])

@otp_bp.route('/forgot_password', methods=['POST'])
def forgot_password():
    """
    Step 1: user POSTs { "username": "...", "email": "..." }.
    We verify that the user exists & email matches, then generate+email a 6‑digit OTP.
    """
    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    email    = data.get('email',    '').strip()
    if not (username and email):
        return jsonify({"error": "Missing username or email"}), 400

    user = g.db.users.find_one({"username": username, "email": email})
    if not user:
        # for security don’t reveal which part failed:
        return jsonify({"message": "If that account exists, you’ll receive a reset code"}), 200

    # generate 6‑digit code
    reset_code = ''.join(random.choices(string.digits, k=6))
    now = datetime.datetime.utcnow()

    # upsert into `resets` (will auto-expire via TTL)
    g.db.resets.update_one(
        {"username": username},
        {"$set": {
            "username":   username,
            "code":       reset_code,
            "created_at": now
        }},
        upsert=True
    )

    # send email
    msg = Message(
        subject="SecureChat Password Reset Code",
        recipients=[email],
        body=(
            f"Hello {username},\n\n"
            f"Your SecureChat password reset code is: {reset_code}\n"
            f"It will expire in {current_app.config['RESET_TTL_SECONDS']//60} minutes.\n\n"
            "If you did not request this, ignore this email.\n"
            "— SecureChat Team"
        )
    )
    try:
        current_app.extensions['mail'].send(msg)
    except Exception as exc:
        current_app.logger.error("Reset‑OTP email failed", exc_info=exc)
        return jsonify({"error": "Failed to send reset code"}), 500

    # Always return 200 so attackers can’t enumerate users
    return jsonify({"message": "If that account exists, you’ll receive a reset code"}), 200


@otp_bp.route('/reset_password', methods=['POST'])
def reset_password():
    """
    Step 2: user POSTs { "username": "...", "code": "...", "password": "newpw" }.
    We verify, update their hash, and delete the reset record.
    """
    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    code_in  = data.get('code',     '').strip()
    password = data.get('password', '').strip()

    if not (username and code_in and password):
        return jsonify({"error": "Missing fields"}), 400

    rec = g.db.resets.find_one({"username": username})
    if not rec or rec.get('code') != code_in:
        return jsonify({"error": "Invalid or expired code"}), 400

    # update password_hash
    new_hash = generate_password_hash(password)
    g.db.users.update_one(
        {"username": username},
        {"$set": {"password_hash": new_hash}}
    )

    # remove reset record
    g.db.resets.delete_one({"username": username})

    return jsonify({"message": "Password updated"}), 200
