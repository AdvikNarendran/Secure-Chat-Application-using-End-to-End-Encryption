# auth_security.py
from flask import Blueprint, request, jsonify, g, current_app, url_for
import datetime, uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message

sec_bp = Blueprint('auth_security', __name__)

# In‑memory maps; in production use MongoDB with TTL indexes
# We'll create collections: login_otps, reset_tokens

@sec_bp.record
def init_indexes(setup):
    db = setup.app.db
    # login OTPs expire in 5 minutes
    db.login_otps.create_index('created_at', expireAfterSeconds=300)
    # reset tokens expire in 1 hour
    db.reset_tokens.create_index('created_at', expireAfterSeconds=3600)
@sec_bp.route('/pre_register', methods=['POST'])
def pre_register():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        return jsonify({'error': 'Missing fields'}), 400

    # Check if user already exists
    if g.db.users.find_one({'username': username}):
        return jsonify({'error': 'Username already exists'}), 409

    # Generate OTP
    otp = uuid.uuid4().hex[:6].upper()
    g.db.reg_otps.update_one(
        {'username': username},
        {'$set': {
            'username': username,
            'email': email,
            'password_hash': generate_password_hash(password),
            'otp': otp,
            'created_at': datetime.datetime.utcnow()
        }},
        upsert=True
    )

    # Send OTP via email
    msg = Message(
        subject='SecureChat Registration Code',
        recipients=[email],
        body=f"Hello {username}, your registration code is: {otp}. It expires in 5 minutes."
    )
    current_app.extensions['mail'].send(msg)

    return jsonify({'message': 'Registration OTP sent'}), 200
@sec_bp.route('/verify_register', methods=['POST'])
def verify_register():
    data = request.get_json() or {}
    username = data.get('username')
    otp = data.get('otp')

    if not username or not otp:
        return jsonify({'error': 'Missing fields'}), 400

    entry = g.db.reg_otps.find_one({'username': username})
    if not entry or entry['otp'] != otp:
        return jsonify({'error': 'Invalid OTP'}), 401

    # Optional: check expiration
    if (datetime.datetime.utcnow() - entry['created_at']).total_seconds() > 300:
        return jsonify({'error': 'OTP expired'}), 410

    # Create user
    g.db.users.insert_one({
        'username': username,
        'email': entry['email'],
        'password_hash': entry['password_hash'],
        'created_at': datetime.datetime.utcnow()
    })

    g.db.reg_otps.delete_one({'username': username})

    return jsonify({'message': 'User registered successfully'}), 200

@sec_bp.route('/login', methods=['POST'])
def login_step1():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    user = g.db.users.find_one({'username': username})
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401
    # generate 6‑digit OTP
    otp = uuid.uuid4().hex[:6].upper()
    g.db.login_otps.update_one(
        {'username': username},
        {'$set': {
            'username': username,
            'otp': otp,
            'created_at': datetime.datetime.utcnow()
        }},
        upsert=True
    )
    # send OTP via email
    msg = Message(
        subject='Your SecureChat Login Code',
        recipients=[user.get('email')],
        body=f"Hello {username}, your login code is: {otp}. It expires in 5 minutes."
    )
    current_app.extensions['mail'].send(msg)
    return jsonify({'message': '2FA code sent'}), 200

@sec_bp.route('/login/verify', methods=['POST'])
def login_step2():
    data = request.get_json() or {}
    username = data.get('username')
    otp = data.get('otp')
    if not username or not otp:
        return jsonify({'error': 'Missing username or OTP'}), 400
    record = g.db.login_otps.find_one({'username': username})
    if not record or record.get('otp') != otp:
        return jsonify({'error': 'Invalid or expired OTP'}), 400
    # OTP valid: issue JWT
    payload = {
        'sub': username,
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = current_app.jwt_encode(payload)
    # cleanup
    g.db.login_otps.delete_one({'username': username})
    return jsonify({'token': token}), 200

@sec_bp.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    if not email:
        return jsonify({'error': 'Email required'}), 400
    user = g.db.users.find_one({'email': email})
    # Always respond success to prevent enumeration
    if user:
        token = uuid.uuid4().hex
        g.db.reset_tokens.insert_one({
            'username': user['username'],
            'token': token,
            'created_at': datetime.datetime.utcnow()
        })
        link = url_for('auth_security.reset_password', token=token, _external=True)
        msg = Message(
            subject='SecureChat Password Reset',
            recipients=[email],
            body=f"Reset your password using the link below (expires in 1 hour):\n{link}"
        )
        current_app.extensions['mail'].send(msg)
    return jsonify({'message': 'If that email exists, you’ll receive a reset link.'}), 200

@sec_bp.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    data = request.get_json() or {}
    new_pw = data.get('password')
    if not new_pw:
        return jsonify({'error': 'Password required'}), 400
    rec = g.db.reset_tokens.find_one({'token': token})
    if not rec:
        return jsonify({'error': 'Invalid or expired token'}), 400
    # update password
    pw_hash = generate_password_hash(new_pw)
    g.db.users.update_one(
        {'username': rec['username']},
        {'$set': {'password_hash': pw_hash}}
    )
    # remove token
    g.db.reset_tokens.delete_one({'token': token})
    return jsonify({'message': 'Password has been reset'}), 200
