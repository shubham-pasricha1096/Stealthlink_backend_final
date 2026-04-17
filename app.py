# app.py - StealthLink OTP + Socket.IO server
# Fixed duplicate messages and single room per QR

import eventlet
eventlet.monkey_patch()  # must be very early for stable socket I/O

import os
import time
import uuid
import logging
import hmac
import hashlib
import struct
import base64
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Try to import QR decoding, but make it optional
try:
    from pyzbar.pyzbar import decode
    from PIL import Image
    QR_SUPPORT = True
    logger.info("QR support enabled")
except ImportError as e:
    QR_SUPPORT = False
    logger.warning(f"QR support disabled: {e}")

# -------------------------
# TOTP Configuration (must match generator)
# -------------------------
T0 = 0           # Unix epoch start
TX = 300         # Time step in seconds (5 minutes)
OTP_LENGTH = 6
VALIDITY_SECONDS = TX

# -------------------------
# Flask + SocketIO config
# -------------------------
app = Flask(__name__)
CORS(app)
app.config['UPLOAD_FOLDER'] = "uploads"
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Required for sessions
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# SocketIO: use eventlet async mode and tune ping settings for mobile networks
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    ping_timeout=60,   # seconds before server treats client as timed out
    ping_interval=25   # how often server pings the client
)

# -------------------------------------------------------
# Load Fernet key and TOTP secret key
# -------------------------------------------------------
FERNET_KEY_PATH = "fernet.key"
TOTP_KEY_PATH = "otp_key.key"

def setup_encryption():
    """Load Fernet key for decrypting payloads"""
    if not os.path.exists(FERNET_KEY_PATH):
        logger.error(f"Missing Fernet key file: {FERNET_KEY_PATH}")
        logger.error("Run the generator first to create fernet.key")
        raise RuntimeError(f"Missing Fernet key file: {FERNET_KEY_PATH}")
    
    with open(FERNET_KEY_PATH, "rb") as f:
        key = f.read()
    logger.info("Fernet encryption key loaded successfully")
    return Fernet(key)

def load_totp_secret():
    """Load TOTP secret key for verification"""
    if not os.path.exists(TOTP_KEY_PATH):
        logger.error(f"Missing TOTP key file: {TOTP_KEY_PATH}")
        logger.error("Run the generator first to create otp_key.key")
        raise RuntimeError(f"Missing TOTP key file: {TOTP_KEY_PATH}")
    
    with open(TOTP_KEY_PATH, "rb") as f:
        key = f.read()
    logger.info("TOTP secret key loaded successfully")
    return key

try:
    fernet = setup_encryption()
    totp_secret = load_totp_secret()
except Exception as e:
    logger.error(f"Failed to initialize keys: {e}")
    raise

# -------------------------------------------------------
# TOTP Verification Functions
# -------------------------------------------------------
def generate_totp(timestamp: int = None) -> str:
    """Generate TOTP using the same algorithm as generator"""
    if timestamp is None:
        timestamp = int(time.time())
    
    # Calculate counter = floor((current_time - T0) / TX)
    counter = int((timestamp - T0) / TX)
    
    # Pack counter into 8-byte big-endian
    counter_bytes = struct.pack(">Q", counter)
    
    # Decode base32 key and compute HMAC-SHA1
    secret = base64.b32decode(totp_secret, casefold=True)
    hmac_hash = hmac.new(secret, counter_bytes, hashlib.sha1).digest()
    
    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code = (struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** OTP_LENGTH)
    return str(code).zfill(OTP_LENGTH)

def verify_totp(otp: str, timestamp: int) -> bool:
    """
    Verify TOTP with time drift tolerance.
    Allows for slight time differences between client and server.
    """
    current_time = int(time.time())
    
    # Check if timestamp is within reasonable range (avoid replay attacks)
    if abs(current_time - timestamp) > 600:  # 10 minutes tolerance
        logger.warning(f"Timestamp too far from current time: {timestamp}")
        return False
    
    # Check current time window
    expected_otp = generate_totp(timestamp)
    if hmac.compare_digest(otp, expected_otp):
        return True
    
    # Also check previous and next time windows for clock drift tolerance
    expected_otp_prev = generate_totp(timestamp - TX)
    if hmac.compare_digest(otp, expected_otp_prev):
        logger.info("TOTP verified with previous time window (clock drift)")
        return True
        
    expected_otp_next = generate_totp(timestamp + TX)
    if hmac.compare_digest(otp, expected_otp_next):
        logger.info("TOTP verified with next time window (clock drift)")
        return True
    
    return False

# -------------------------------------------------------
# In-memory session and connection tracking
# active_sessions: { otp_string: {"users": [user_id1,...], "timestamp": epoch, "room_ready": bool} }
# connected_users: { socket_id: {"otp": otp, "user_id": user_id, "username": username} }
# -------------------------------------------------------
active_sessions = {}
connected_users = {}

# -------------------------
# Helper: cleanup stale sessions
# -------------------------
def cleanup_sessions(max_age_seconds=600):
    """Remove sessions older than max_age_seconds."""
    now = int(time.time())
    remove = []
    for otp, sess in active_sessions.items():
        if now - sess.get("timestamp", now) > max_age_seconds:
            remove.append(otp)
    for otp in remove:
        active_sessions.pop(otp, None)
        logger.info(f"Cleaned up expired session: {otp}")

# -------------------------------------------------------
# Helper: Generate test encrypted payload for debugging
# -------------------------------------------------------
def generate_test_payload():
    """Generate a test encrypted payload for debugging purposes"""
    test_otp = generate_totp()
    timestamp = int(time.time())
    payload = f"{test_otp}|{timestamp}"
    encrypted = fernet.encrypt(payload.encode()).decode()
    return encrypted, test_otp, timestamp

# -------------------------------------------------------
# API: verify_otp - client POSTs {"encrypted_otp": "...", "user_id": "..."} 
# returns: waiting / ready / expired / invalid
# -------------------------------------------------------
@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    try:
        # Check content type
        if not request.is_json:
            return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400
            
        data = request.get_json(force=True)
        encrypted_text = data.get("encrypted_otp")
        user_id = data.get("user_id") or str(uuid.uuid4())

        logger.info(f"OTP verification request from user: {user_id}")

        if not encrypted_text:
            return jsonify({"status": "error", "message": "No OTP provided"}), 400

        # Input validation
        if not isinstance(encrypted_text, str) or len(encrypted_text) < 10:
            return jsonify({"status": "invalid", "message": "Invalid OTP format"}), 400

        # decrypt - format expected: "<otp>|<timestamp>"
        try:
            decrypted_data = fernet.decrypt(encrypted_text.encode()).decode()
            otp, ts = decrypted_data.split("|")
            ts = int(ts)
            logger.info(f"Decrypted OTP: {otp}, timestamp: {ts}")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return jsonify({"status": "invalid", "message": "Invalid OTP"}), 400

        # Verify TOTP
        if not verify_totp(otp, ts):
            logger.warning(f"TOTP verification failed for OTP: {otp}")
            return jsonify({"status": "invalid", "message": "Invalid OTP"}), 400

        # Check if OTP is expired (using timestamp from payload)
        current_time = int(time.time())
        if current_time - ts > VALIDITY_SECONDS:
            logger.info(f"OTP expired: {otp} (timestamp: {ts})")
            return jsonify({"status": "expired", "message": "OTP has expired"}), 400

        # Check if session already exists
        session = active_sessions.get(otp)
        if not session:
            # Create new session - first user
            session = {
                "users": [user_id],
                "timestamp": current_time,
                "room_ready": False  # Room not ready until second user joins
            }
            active_sessions[otp] = session
            logger.info(f"New session created for OTP: {otp} with user: {user_id}")
        else:
            # Add user to existing session if not already present
            if user_id not in session["users"]:
                session["users"].append(user_id)
                logger.info(f"User {user_id} added to session {otp}. Total users: {len(session['users'])}")
            session["timestamp"] = current_time

        # optional cleanup
        cleanup_sessions()

        user_count = len(session["users"])
        
        if user_count >= 2:
            # Mark room as ready when second user joins
            if not session.get("room_ready", False):
                session["room_ready"] = True
                logger.info(f"Room marked as ready for OTP: {otp} with users {session['users']}")
            
            return jsonify({
                "status": "ready", 
                "otp": otp, 
                "user_id": user_id,
                "user_count": user_count
            }), 200
        else:
            # First user waiting for second user
            return jsonify({
                "status": "waiting", 
                "otp": otp, 
                "user_id": user_id,
                "user_count": user_count
            }), 200

    except Exception as e:
        logger.error(f"Verify OTP error: {str(e)}")
        return jsonify({"status": "invalid", "message": "Internal server error"}), 500

# -------------------------------------------------------
# Web UI: manual decrypt / upload (for testing)
# -------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    decrypted_otp = None
    error = None
    encrypted_text = ""
    timestamp = None

    if request.method == "POST":
        # 1) Plain encrypted text posted
        if "encrypted_otp" in request.form:
            encrypted_text = request.form.get("encrypted_otp", "").strip()
            logger.info(f"Form OTP submitted: {encrypted_text[:50]}...")

        # 2) QR image uploaded (if supported)
        elif "qr_image" in request.files and QR_SUPPORT:
            image = request.files["qr_image"]
            if image and image.filename != "":
                path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
                try:
                    image.save(path)
                    qr_data = decode(Image.open(path))
                    if qr_data:
                        encrypted_text = qr_data[0].data.decode()
                        logger.info(f"QR decoded: {encrypted_text[:50]}...")
                    else:
                        error = "No QR code found in the image."
                        logger.warning("No QR code found in uploaded image")
                except Exception as exc:
                    error = "Failed to read QR image."
                    logger.error(f"QR decode error: {exc}")
        elif "qr_image" in request.files and not QR_SUPPORT:
            error = "QR decoding is not supported on this server."

        # decrypt and verify
        if encrypted_text:
            try:
                decrypted_data = fernet.decrypt(encrypted_text.encode()).decode()
                otp, ts = decrypted_data.split("|")
                ts = int(ts)
                
                # Verify TOTP
                if not verify_totp(otp, ts):
                    error = "Invalid OTP."
                    logger.info(f"Invalid OTP in UI: {otp}")
                else:
                    current_time = int(time.time())
                    if current_time - ts > VALIDITY_SECONDS:
                        error = "OTP has expired."
                        logger.info(f"Expired OTP in UI: {otp}")
                    else:
                        decrypted_otp = otp
                        timestamp = ts
                        logger.info(f"Successfully decrypted and verified OTP: {otp}")
                        
            except Exception as exc:
                logger.error(f"UI decryption failed: {exc}")
                error = "Decryption failed. Please check the OTP."

    return render_template("index.html", 
                         otp=decrypted_otp, 
                         timestamp=timestamp,
                         error=error, 
                         qr_support=QR_SUPPORT,
                         validity_seconds=VALIDITY_SECONDS)

# -------------------------------------------------------
# Generate test encrypted payload endpoint
# -------------------------------------------------------
@app.route("/generate_test_payload", methods=["GET"])
def generate_test_endpoint():
    """Endpoint to generate a test encrypted payload for debugging"""
    try:
        encrypted, decrypted_otp, timestamp = generate_test_payload()
        return jsonify({
            "encrypted_otp": encrypted,
            "decrypted_otp": decrypted_otp,
            "timestamp": timestamp,
            "current_time": int(time.time()),
            "message": "Test payload generated successfully"
        })
    except Exception as e:
        logger.error(f"Test payload generation failed: {e}")
        return jsonify({"error": "Failed to generate test payload"}), 500

# -------------------------------------------------------
# Health check endpoint
# -------------------------------------------------------
@app.route("/health", methods=["GET"])
def health_check():
    current_otp = generate_totp()
    return jsonify({
        "status": "healthy",
        "timestamp": time.time(),
        "current_otp": current_otp,
        "active_sessions": len(active_sessions),
        "connected_users": len(connected_users),
        "qr_support": QR_SUPPORT,
        "totp_config": {
            "t0": T0,
            "tx": TX,
            "otp_length": OTP_LENGTH,
            "validity_seconds": VALIDITY_SECONDS
        }
    })

# -------------------------------------------------------
# Polling helper: session status by OTP
# -------------------------------------------------------
@app.route("/session_status/<otp>", methods=["GET"])
def check_session_status(otp):
    session = active_sessions.get(otp)
    if not session:
        return jsonify({"status": "invalid"}), 404
    
    user_count = len(session["users"])
    if user_count >= 2 and session.get("room_ready", False):
        return jsonify({"status": "ready", "user_count": user_count}), 200
    else:
        return jsonify({"status": "waiting", "user_count": user_count}), 200

# -------------------------------------------------------
# List active sessions (for debugging)
# -------------------------------------------------------
@app.route("/debug/sessions", methods=["GET"])
def debug_sessions():
    cleanup_sessions()
    return jsonify({
        "active_sessions": active_sessions,
        "connected_users": connected_users,
        "total_sessions": len(active_sessions),
        "total_connected": len(connected_users)
    })

# -------------------------------------------------------
# Current TOTP value (for debugging)
# -------------------------------------------------------
@app.route("/debug/current_totp", methods=["GET"])
def debug_current_totp():
    current_time = int(time.time())
    current_otp = generate_totp(current_time)
    prev_otp = generate_totp(current_time - TX)
    next_otp = generate_totp(current_time + TX)
    
    return jsonify({
        "current_time": current_time,
        "current_otp": current_otp,
        "previous_otp": prev_otp,
        "next_otp": next_otp,
        "time_window": f"{(current_time - T0) // TX}"
    })

# -------------------------------------------------------
# Socket.IO events - chat relay 
# -------------------------------------------------------
@socketio.on("connect")
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on("disconnect")
def handle_disconnect():
    # Remove user from connected_users tracking
    user_info = connected_users.pop(request.sid, None)
    if user_info:
        logger.info(f"Client disconnected: {request.sid} (User: {user_info.get('username')})")
    else:
        logger.info(f"Client disconnected: {request.sid}")

@socketio.on("join_room")
def handle_join(data):
    otp = data.get("otp")
    username = data.get("username")
    user_id = data.get("user_id")
    
    if not otp or not username:
        logger.warning("Join room attempted without OTP or username")
        emit("error", {"message": "Missing OTP or username"})
        return
    
    # Check if session exists and is ready
    session = active_sessions.get(otp)
    if not session:
        logger.warning(f"Join room attempted for non-existent session: {otp}")
        emit("error", {"message": "Session not found. Please scan the QR code again."})
        return
    
    if not session.get("room_ready", False):
        logger.warning(f"Join room attempted for non-ready session: {otp}")
        emit("error", {"message": "Chat room not ready yet. Wait for another user to join."})
        return
    
    # Track connected user
    connected_users[request.sid] = {
        "otp": otp,
        "user_id": user_id,
        "username": username
    }
    
    # Join the room
    join_room(otp)
    
    # Send join notification to OTHER users only (not the sender)
    emit("system", {"message": f"{username} joined the chat"}, room=otp, include_self=False)
    
    # Send welcome message to the joining user only
    emit("system", {"message": f"Welcome to the chat! You joined room {otp}"})
    
    logger.info(f"[JOIN] {username} joined room {otp}. Room users: {session['users']}")

@socketio.on("send_message")
def handle_message(data):
    otp = data.get("otp")
    username = data.get("username")
    message = data.get("message")
    timestamp = int(time.time())
    
    if not otp or not message:
        return
    
    # Verify the room exists and is active
    session = active_sessions.get(otp)
    if not session or not session.get("room_ready", False):
        logger.warning(f"Message attempted for invalid session: {otp}")
        return
        
    # Relay message to everyone EXCEPT the sender
    emit("receive_message", {
        "username": username, 
        "message": message, 
        "timestamp": timestamp
    }, room=otp, include_self=False)
    
    logger.info(f"[MESSAGE] {username}@{otp}: {message if len(str(message))<200 else '[long]'}")

@socketio.on("leave_room")
def handle_leave(data):
    otp = data.get("otp")
    username = data.get("username")
    
    if not otp:
        return
    
    # Remove from tracking
    connected_users.pop(request.sid, None)
    
    leave_room(otp)
    
    # Only send leave message if room still exists and is ready
    session = active_sessions.get(otp)
    if session and session.get("room_ready", False):
        emit("system", {"message": f"{username} left the chat"}, room=otp, include_self=False)
    
    logger.info(f"[LEAVE] {username} left room {otp}")

# -------------------------------------------------------
# Run server with eventlet
# -------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting StealthLink TOTP Server...")
    logger.info(f"QR Support: {QR_SUPPORT}")
    logger.info(f"TOTP Configuration: TX={TX}s, OTP_LENGTH={OTP_LENGTH}")
    logger.info("Server will be available at http://localhost:5000")
    logger.info("Test endpoints:")
    logger.info("  - GET  /health (health check)")
    logger.info("  - GET  /generate_test_payload (generate test encrypted payload)")
    logger.info("  - GET  /debug/current_totp (view current TOTP values)")
    logger.info("  - GET  /debug/sessions (view active sessions)")
    
    # Note: debug=False recommended for SocketIO stability during dev
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, log_output=True)