import os
import hmac
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

# Imports for Google Auth
from google.oauth2 import id_token
from google.auth.transport import requests as google_auth_requests
import requests as http_requests

app = Flask(__name__)

# --- CONFIGURATION ---
# Admin app doesn't need these, but User app does to verify identity
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
SESSION_SECRET = os.environ.get("SESSION_SECRET", "change-this-secret-now")
# DATABASE_URL must be the SAME as in the Admin repo
DB_URL = os.environ.get("DATABASE_URL")

# --- DATABASE CONNECTION ---
if DB_URL:
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DB_URL)
else:
    # Fallback for local testing only
    engine = create_engine("sqlite:///temp_user.db")

# --- DATABASE INITIALIZATION ---
# We check/create tables to ensure they exist, even if Admin creates them first.
def init_db():
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS active_sessions (
                user_email TEXT PRIMARY KEY,
                expires_at TIMESTAMP
            );
        """))
        # We also check other tables just in case, but we primarily rely on them
        # being created by the Admin App.
        conn.commit()

with app.app_context():
    init_db()

# --- HELPER FUNCTIONS ---

def generate_session_token(email, hours):
    expiry = datetime.now() + timedelta(hours=hours)
    expiry_str = expiry.isoformat()
    message = f"{email}:{expiry_str}"
    signature = hmac.new(
        SESSION_SECRET.encode(), message.encode(), hashlib.sha256
    ).hexdigest()[:16]
    return f"{email}:{expiry_str}:{signature}"

def verify_google_token(token, token_type="access_token"):
    if token_type == "id_token":
        try:
            idinfo = id_token.verify_oauth2_token(
                token, google_auth_requests.Request(), GOOGLE_CLIENT_ID
            )
            if not idinfo.get('email_verified', False): return None, "Email not verified"
            return idinfo.get('email'), None
        except Exception as e: return None, str(e)
    else:
        try:
            response = http_requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {token}"}, timeout=10
            )
            if response.status_code != 200: return None, "Invalid token"
            return response.json().get('email'), None
        except Exception as e: return None, str(e)

# --- ROUTES ---

@app.route('/')
def home():
    return "User API Live. Connecting to shared database..."

@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json or {}
    google_token = data.get('google_token')
    token_type = data.get('token_type', 'access_token')
    provided_key = data.get('key')
    requested_file = data.get('requested_file')

    if not google_token:
        return jsonify({"authorized": False, "error": "Google token required"}), 400

    # 1. Verify Identity
    email, error = verify_google_token(google_token, token_type)
    if error:
        return jsonify({"authorized": False, "error": f"Google auth failed: {error}"}), 403

    gdrive_id_to_return = None

    with engine.connect() as conn:
        # 2. Check Session (in active_sessions table)
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"), {"e": email}
        ).fetchone()

        if session:
            expires_at = session[0]
            if isinstance(expires_at, str): expires_at = datetime.fromisoformat(expires_at)
            
            if datetime.now() < expires_at:
                remaining = (expires_at - datetime.now()).total_seconds() / 3600
                
                # 3. GET THE REQUESTED FILE ID (from file_registry table)
                if requested_file:
                    file_row = conn.execute(
                        text("SELECT gdrive_id FROM file_registry WHERE name = :n"), 
                        {"n": requested_file}
                    ).fetchone()
                    if file_row:
                        gdrive_id_to_return = file_row[0]
                    else:
                        return jsonify({"authorized": False, "error": f"File '{requested_file}' not found on server."}), 404
                else:
                    # Fallback: try to get first file
                    row = conn.execute(text("SELECT gdrive_id FROM file_registry LIMIT 1")).fetchone()
                    gdrive_id_to_return = row[0] if row else "DEFAULT_FALLBACK_ID"

                return jsonify({
                    "authorized": True, "email": email, "hours_remaining": round(remaining, 2),
                    "gdrive_id": gdrive_id_to_return,
                    "session_token": generate_session_token(email, remaining)
                })
            else:
                conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
                conn.commit()

        # 4. Check License Key (from licenses table)
        if not provided_key:
            return jsonify({"authorized": False, "needs_key": True, "error": "Active license required."}), 401

        row = conn.execute(
            text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"), {"k": provided_key}
        ).fetchone()

        if not row: return jsonify({"authorized": False, "error": "Invalid license key"}), 403
        if row[0] == 'used': return jsonify({"authorized": False, "error": "Key already used"}), 403

        # 5. Activate
        new_expiry = datetime.now() + timedelta(hours=row[1])
        conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
        conn.execute(text("INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)"), {"e": email, "t": new_expiry})
        conn.commit()

        # Determine File
        if requested_file:
            file_row = conn.execute(text("SELECT gdrive_id FROM file_registry WHERE name = :n"), {"n": requested_file}).fetchone()
            gdrive_id_to_return = file_row[0] if file_row else "DEFAULT_FALLBACK_ID"
        else:
            row = conn.execute(text("SELECT gdrive_id FROM file_registry LIMIT 1")).fetchone()
            gdrive_id_to_return = row[0] if row else "DEFAULT_FALLBACK_ID"

        return jsonify({
            "authorized": True, "message": f"Activated for {row[1]} hours",
            "email": email, "hours_remaining": row[1],
            "gdrive_id": gdrive_id_to_return,
            "session_token": generate_session_token(email, row[1])
        })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
