import os
import datetime
import eventlet
eventlet.monkey_patch()

from flask import Flask, send_from_directory, g, request, jsonify, current_app
from flask_cors import CORS
from flask_socketio import SocketIO
from pymongo import MongoClient
from flask_mail import Mail
import jwt

# ─── Local Blueprint Imports ─────────────────────────────────────────────
from auth import auth_bp                 # login & (overridden) /auth/register
from auth_security import sec_bp         # 2FA login & password reset
from keys import key_bp, jwt_required    # /keys/* and decorator
from roster import roster_bp            # /users
from chat import ChatNamespace           # Socket.IO namespace
from auth_otp import otp_bp, init_app as init_otp  # pre_register + OTP register

# ─── Flask App Setup ─────────────────────────────────────────────────────
app = Flask(__name__, static_folder=None)

# ─── Inline Configuration ────────────────────────────────────────────────
app.config['JWT_SECRET']    = os.getenv('JWT_SECRET', 'supersecret')
app.config['JWT_ALGORITHM'] = os.getenv('JWT_ALGORITHM', 'HS256')

# reCAPTCHA (Hardcoded)
app.config['RECAPTCHA_SECRET'] = "6LfmTTwrAAAAAO2YQ-2TuIHV1XoxxKX3mTzkTLyQ"

# Mail (Flask‑Mail)
app.config['MAIL_SERVER']         = "smtp.gmail.com"
app.config['MAIL_PORT']           = 587
app.config['MAIL_USE_TLS']        = True
app.config['MAIL_USERNAME']       = os.getenv('MAIL_USERNAME', 'darkx7877@gmail.com')
app.config['MAIL_PASSWORD']       = os.getenv('MAIL_PASSWORD', 'sjfwyilfwzxtjxhw')
app.config['MAIL_DEFAULT_SENDER']= ("SecureChat", "no-reply@yourdomain.com")

# OTP lifetime
app.config['OTP_TTL_SECONDS']    = 300  # 5 minutes
app.config['RESET_TTL_SECONDS']  = 300  # 5 minutes for reset OTP

# ─── Extensions Initialization ───────────────────────────────────────────
CORS(app)
mail = Mail(app)

# ─── JWT Helper ─────────────────────────────────────────────────────────
def jwt_encode(payload):
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm=app.config['JWT_ALGORITHM'])

app.jwt_encode = jwt_encode

# ─── MongoDB Initialization ───────────────────────────────────────────────
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://127.0.0.1:27017/')
mongo_client = MongoClient(MONGO_URI)
db = mongo_client[os.getenv('MONGO_DB', 'secure_chat_db')]

app.db = db
@app.before_request
def _inject_db():
    g.db = db

# ─── Blueprint Registration ───────────────────────────────────────────────
app.register_blueprint(otp_bp,   url_prefix="/auth")
app.register_blueprint(sec_bp,   url_prefix="/auth")
app.register_blueprint(auth_bp,  url_prefix="/auth")
app.register_blueprint(key_bp,   url_prefix="/keys")
app.register_blueprint(roster_bp)

# ─── Message Persistence Endpoints ────────────────────────────────────────
@app.route('/messages', methods=['POST'])
@jwt_required
def save_message():
    data = request.get_json() or {}
    sender = g.current_user
    # Ensure the sender matches the authenticated user
    if data.get('from') != sender:
        return jsonify({'error': 'Unauthorized sender'}), 403
    # Insert into MongoDB
    g.db.messages.insert_one({
        **data,
        'timestamp': datetime.datetime.utcnow()
    })
    return jsonify({'message': 'Message saved'}), 200

@app.route('/messages/<peer>', methods=['GET'])
@jwt_required
def get_messages(peer):
    user = g.current_user
    # Fetch conversation between user and peer
    cursor = g.db.messages.find({
        '$or': [
            {'from': user, 'to': peer},
            {'from': peer, 'to': user}
        ]
    }).sort('timestamp', 1)
    history = []
    for msg in cursor:
        # Convert BSON datetime to ISO string
        history.append({
            'from': msg['from'],
            'to': msg['to'],
            'ciphertext': msg['ciphertext'],
            'iv': msg['iv'],
            'ephemeralPubKey': msg.get('ephemeralPubKey'),
            'signature': msg.get('signature'),
            'timestamp': msg['timestamp'].isoformat()
        })
    return jsonify(history), 200

# ─── Socket.IO Setup ─────────────────────────────────────────────────────
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")
socketio.on_namespace(ChatNamespace("/chat"))

# ─── Static File Routes ───────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("templates", "index.html")

@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)

# ─── Initialize OTP subsystem ─────────────────────────────────────────────
init_otp(app)

# ─── Main Entrypoint ──────────────────────────────────────────────────────
if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)
