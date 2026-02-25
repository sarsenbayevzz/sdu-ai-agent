import os
import sqlite3
import hashlib
import secrets
import asyncio
import threading
import time
import json
from flask import Flask, jsonify, request
from flask_cors import CORS
from groq import Groq
from dotenv import load_dotenv

try:
    import h3 as h3lib
    H3_AVAILABLE = True
except ImportError:
    H3_AVAILABLE = False

load_dotenv()

app = Flask(__name__)
CORS(app)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
groq_client = Groq(api_key=GROQ_API_KEY)

DB_PATH = os.getenv("DB_PATH", "sdu_agent.db")

STUDENT = {
    "name": "Azhar",
    "major": "Computer Science",
    "semester": 3,
    "gpa": 3.45,
    "courses": ["Data Structures", "Algorithms", "Calculus II", "Database Systems"],
    "assignments": [
        {"course": "Data Structures", "title": "Binary Tree Implementation", "due": "Feb 20"},
        {"course": "Calculus II", "title": "Integration Problem Set", "due": "Feb 22"},
    ],
}

SYSTEM_PROMPT = f"""You are the SDU AI Agent for Suleyman Demirel University.
You are helping a student named {STUDENT['name']}.

STUDENT INFO:
- Major: {STUDENT['major']}
- Semester: {STUDENT['semester']}
- GPA: {STUDENT['gpa']}
- Courses: {', '.join(STUDENT['courses'])}
- Pending assignments:
  * Data Structures: Binary Tree Implementation (due Feb 20)
  * Calculus II: Integration Problem Set (due Feb 22)

YOUR RULES:
1. NEVER give direct answers to homework problems
2. Use Socratic method - ask guiding questions instead
3. Be friendly and encouraging
4. When student asks about homework, show their assignments
5. When student asks about schedule, show their courses
6. Help them UNDERSTAND, not just get answers

SOCRATIC METHOD EXAMPLE:
Student: "What is the answer to this integral?"
You: "Great question! Before we solve it, what do you
     know about the relationship between integration
     and differentiation?"
"""

_sessions = {}
_event_loop = None
_event_queue = None


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            sharing_enabled INTEGER DEFAULT 0,
            h3_home_zone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conv_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (conv_id) REFERENCES conversations(id)
        );

        CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            lat REAL NOT NULL,
            lng REAL NOT NULL,
            h3_index TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_a INTEGER NOT NULL,
            user_b INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_a) REFERENCES users(id),
            FOREIGN KEY (user_b) REFERENCES users(id),
            UNIQUE(user_a, user_b)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS location_stats (
            h3_index TEXT PRIMARY KEY,
            zone_name TEXT,
            user_count INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS moodle_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course TEXT NOT NULL,
            assignments_json TEXT,
            fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.commit()
    conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, hashed):
    return hash_password(password) == hashed


def create_session(user_id, role):
    token = secrets.token_hex(32)
    _sessions[token] = {"user_id": user_id, "role": role, "ts": time.time()}
    return token


def get_user_from_token(token):
    if not token:
        return None
    session = _sessions.get(token)
    if not session:
        return None
    if time.time() - session["ts"] > 86400:
        _sessions.pop(token, None)
        return None
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    db.close()
    return dict(row) if row else None


def require_roles(token, roles):
    user = get_user_from_token(token)
    if not user:
        return None
    if user["role"] not in roles:
        return None
    return user


def audit(user_id, action, details=None, ip=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?,?,?,?)",
        (user_id, action, details, ip),
    )
    db.commit()
    db.close()


def latlng_to_h3(lat, lng):
    if H3_AVAILABLE:
        if hasattr(h3lib, "latlng_to_cell"):
            return h3lib.latlng_to_cell(lat, lng, 11)
        return h3lib.geo_to_h3(lat, lng, 11)
    tile = 360.0 / (2 ** 13)
    li = int((lat + 90) / tile)
    lo = int((lng + 180) / tile)
    return f"8b{li:09x}{lo:06x}ff"


def can_see_location(requester_id, target_id):
    if requester_id == target_id:
        return True, "own"
    db = get_db()
    target = db.execute("SELECT sharing_enabled FROM users WHERE id = ?", (target_id,)).fetchone()
    if not target or not target["sharing_enabled"]:
        db.close()
        return False, "sharing_disabled"
    friendship = db.execute(
        "SELECT status FROM friendships WHERE "
        "(user_a=? AND user_b=?) OR (user_a=? AND user_b=?)",
        (requester_id, target_id, target_id, requester_id),
    ).fetchone()
    db.close()
    if not friendship or friendship["status"] != "accepted":
        return False, "not_friends"
    return True, "ok"


def publish_event(event_type, payload):
    if _event_queue and _event_loop:
        asyncio.run_coroutine_threadsafe(
            _event_queue.put({"type": event_type, "payload": payload}),
            _event_loop,
        )


async def event_worker():
    while True:
        event = await _event_queue.get()
        try:
            etype = event["type"]
            payload = event["payload"]
            if etype == "location_updated":
                uid = payload.get("user_id")
                h3i = payload.get("h3_index")
                db = get_db()
                db.execute(
                    "INSERT INTO location_stats (h3_index, user_count) VALUES (?,1) "
                    "ON CONFLICT(h3_index) DO UPDATE SET user_count=user_count+1, last_updated=CURRENT_TIMESTAMP",
                    (h3i,),
                )
                db.commit()
                db.close()
                audit(uid, "LOCATION_SHARED", f"h3_index={h3i}")
            elif etype == "chat_message":
                audit(payload.get("user_id"), "CHAT_MESSAGE", f"conv_id={payload.get('conv_id')}")
        except Exception:
            pass
        finally:
            _event_queue.task_done()


def start_event_worker():
    global _event_loop, _event_queue
    _event_loop = asyncio.new_event_loop()
    _event_queue = asyncio.Queue()

    def run():
        _event_loop.run_until_complete(event_worker())

    t = threading.Thread(target=run, daemon=True)
    t.start()


@app.route("/")
def home():
    return "SDU AI Agent Backend is running! 🎓"


@app.route("/api/student", methods=["GET"])
def get_student():
    return jsonify(STUDENT)


@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json()
    user_message = data.get("message", "")
    history = data.get("history", [])
    token = request.headers.get("Authorization", "")
    user = get_user_from_token(token)

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for item in history:
        messages.append(item)
    messages.append({"role": "user", "content": user_message})

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            max_tokens=500,
            temperature=0.7,
        )
        ai_response = response.choices[0].message.content
    except Exception as e:
        ai_response = "Sorry, I'm having trouble connecting right now. Please try again."

    if user:
        db = get_db()
        db.execute(
            "INSERT INTO conversations (user_id, title) VALUES (?,?) ",
            (user["id"], user_message[:60]),
        )
        db.commit()
        conv_id = db.execute(
            "SELECT id FROM conversations WHERE user_id=? ORDER BY created_at DESC LIMIT 1",
            (user["id"],),
        ).fetchone()["id"]
        db.execute("INSERT INTO messages (conv_id, role, content) VALUES (?,?,?)", (conv_id, "user", user_message))
        db.execute("INSERT INTO messages (conv_id, role, content) VALUES (?,?,?)", (conv_id, "assistant", ai_response))
        db.commit()
        db.close()
        publish_event("chat_message", {"user_id": user["id"], "conv_id": conv_id})
        audit(user["id"], "CHAT_MESSAGE", f"msg={user_message[:80]}", request.remote_addr)

    return jsonify({"response": ai_response})


@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")
    role = data.get("role", "student")

    if not username or not email or not password:
        return jsonify({"error": "username, email and password required"}), 400
    if role not in ("student", "advisor", "admin"):
        return jsonify({"error": "invalid role"}), 400

    db = get_db()
    if db.execute("SELECT id FROM users WHERE email=? OR username=?", (email, username)).fetchone():
        db.close()
        return jsonify({"error": "user already exists"}), 409

    db.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
        (username, email, hash_password(password), role),
    )
    db.commit()
    user_id = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    db.close()
    audit(user_id, "REGISTER", f"role={role}", request.remote_addr)
    return jsonify({"message": "registered", "user_id": user_id}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (data.get("email", ""),)).fetchone()
    db.close()
    if not user or not verify_password(data.get("password", ""), user["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401
    token = create_session(user["id"], user["role"])
    audit(user["id"], "LOGIN", None, request.remote_addr)
    return jsonify({"token": token, "role": user["role"], "username": user["username"]})


@app.route("/auth/me", methods=["GET"])
def me():
    user = get_user_from_token(request.headers.get("Authorization", ""))
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    user.pop("password_hash", None)
    return jsonify(user)


@app.route("/location/share", methods=["POST"])
def share_location():
    user = require_roles(request.headers.get("Authorization", ""), ["student", "admin"])
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json()
    lat, lng = data.get("lat"), data.get("lng")
    if lat is None or lng is None:
        return jsonify({"error": "lat and lng required"}), 400
    h3i = latlng_to_h3(float(lat), float(lng))
    db = get_db()
    db.execute("INSERT INTO locations (user_id, lat, lng, h3_index) VALUES (?,?,?,?)", (user["id"], lat, lng, h3i))
    db.execute("UPDATE users SET sharing_enabled=1 WHERE id=?", (user["id"],))
    db.commit()
    db.close()
    publish_event("location_updated", {"user_id": user["id"], "h3_index": h3i})
    return jsonify({"h3_index": h3i, "message": "location shared"})


@app.route("/location/friends", methods=["GET"])
def friend_zones():
    user = require_roles(request.headers.get("Authorization", ""), ["student", "admin"])
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    friends = db.execute(
        "SELECT user_a AS fid FROM friendships WHERE user_b=? AND status='accepted' "
        "UNION SELECT user_b FROM friendships WHERE user_a=? AND status='accepted'",
        (user["id"], user["id"]),
    ).fetchall()
    result = []
    for f in friends:
        fid = f["fid"]
        allowed, _ = can_see_location(user["id"], fid)
        if not allowed:
            continue
        loc = db.execute(
            "SELECT h3_index, updated_at FROM locations WHERE user_id=? ORDER BY updated_at DESC LIMIT 1", (fid,)
        ).fetchone()
        fname = db.execute("SELECT username FROM users WHERE id=?", (fid,)).fetchone()
        if loc and fname:
            result.append({"friend": fname["username"], "h3_zone": loc["h3_index"], "last_seen": loc["updated_at"]})
    db.close()
    audit(user["id"], "FRIEND_ZONES_QUERIED", None, request.remote_addr)
    return jsonify(result)


@app.route("/location/<int:target_id>", methods=["GET"])
def get_location(target_id):
    user = require_roles(request.headers.get("Authorization", ""), ["student", "advisor", "admin"])
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    allowed, reason = can_see_location(user["id"], target_id)
    audit(user["id"], "LOCATION_ACCESS", f"target={target_id} allowed={allowed} reason={reason}", request.remote_addr)
    if not allowed:
        return jsonify({"error": f"access denied: {reason}"}), 403
    db = get_db()
    loc = db.execute(
        "SELECT h3_index, updated_at FROM locations WHERE user_id=? ORDER BY updated_at DESC LIMIT 1", (target_id,)
    ).fetchone()
    db.close()
    if not loc:
        return jsonify({"error": "no location data"}), 404
    return jsonify({"h3_zone": loc["h3_index"], "last_seen": loc["updated_at"]})


@app.route("/location/friend-request", methods=["POST"])
def friend_request():
    user = require_roles(request.headers.get("Authorization", ""), ["student", "admin"])
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json()
    target_id = data.get("target_id")
    action = data.get("action", "request")
    db = get_db()
    if action == "request":
        try:
            db.execute("INSERT INTO friendships (user_a, user_b, status) VALUES (?,?,'pending')", (user["id"], target_id))
            db.commit()
        except Exception:
            db.close()
            return jsonify({"error": "request already exists"}), 409
    elif action == "accept":
        db.execute(
            "UPDATE friendships SET status='accepted' WHERE user_a=? AND user_b=?", (target_id, user["id"])
        )
        db.commit()
    db.close()
    audit(user["id"], "FRIEND_ACTION", f"action={action} target={target_id}")
    return jsonify({"message": f"friendship {action} processed"})

@app.route("/moodle/assignments", methods=["GET"])
def moodle_assignments():
    user = require_roles(request.headers.get("Authorization", ""), ["student", "admin"])
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    cached = db.execute(
        "SELECT assignments_json, fetched_at FROM moodle_cache WHERE user_id=? ORDER BY fetched_at DESC LIMIT 1",
        (user["id"],),
    ).fetchone()
    if cached:
        db.close()
        audit(user["id"], "MOODLE_VIEWED", "source=cache")
        return jsonify({"source": "cache", "data": json.loads(cached["assignments_json"]), "fetched_at": cached["fetched_at"]})
    data = {
        "CS301": {"course": "Data Structures", "assignments": [
            {"title": "Binary Tree Implementation", "due": "Feb 20", "grade": None},
        ]},
        "MATH201": {"course": "Calculus II", "assignments": [
            {"title": "Integration Problem Set", "due": "Feb 22", "grade": None},
        ]},
    }
    db.execute("INSERT INTO moodle_cache (user_id, course, assignments_json) VALUES (?,?,?)", (user["id"], "all", json.dumps(data)))
    db.commit()
    db.close()
    audit(user["id"], "MOODLE_VIEWED", "source=live")
    return jsonify({"source": "live", "data": data})


@app.route("/moodle/schedule", methods=["GET"])
def moodle_schedule():
    user = require_roles(request.headers.get("Authorization", ""), ["student", "admin"])
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    schedule = {
        "Monday":    ["Data Structures 09:00 — Room 201", "Calculus II 14:00 — Room 105"],
        "Wednesday": ["Algorithms 11:00 — Room 303", "Database Systems 13:00 — Room 202"],
        "Friday":    ["Data Structures 09:00 — Room 201"],
    }
    audit(user["id"], "SCHEDULE_VIEWED", None, request.remote_addr)
    return jsonify(schedule)


@app.route("/analytics/heatmap", methods=["GET"])
def heatmap():
    user = require_roles(request.headers.get("Authorization", ""), ["admin"])
    if not user:
        return jsonify({"error": "admin only"}), 403
    db = get_db()
    rows = db.execute("SELECT h3_index, zone_name, user_count, last_updated FROM location_stats ORDER BY user_count DESC").fetchall()
    db.close()
    audit(user["id"], "HEATMAP_VIEWED", None, request.remote_addr)
    return jsonify([dict(r) for r in rows])


@app.route("/analytics/zone-summary", methods=["GET"])
def zone_summary():
    user = require_roles(request.headers.get("Authorization", ""), ["admin"])
    if not user:
        return jsonify({"error": "admin only"}), 403
    db = get_db()
    rows = db.execute(
        "SELECT l.h3_index, COUNT(DISTINCT l.user_id) AS unique_users, MAX(l.updated_at) AS last_activity "
        "FROM locations l GROUP BY l.h3_index ORDER BY unique_users DESC"
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/users", methods=["GET"])
def admin_users():
    user = require_roles(request.headers.get("Authorization", ""), ["admin"])
    if not user:
        return jsonify({"error": "admin only"}), 403
    db = get_db()
    rows = db.execute("SELECT id, username, email, role, sharing_enabled, h3_home_zone, created_at FROM users").fetchall()
    db.close()
    audit(user["id"], "ADMIN_USERS_LISTED", None, request.remote_addr)
    return jsonify([dict(r) for r in rows])


@app.route("/admin/audit", methods=["GET"])
def admin_audit():
    user = require_roles(request.headers.get("Authorization", ""), ["admin"])
    if not user:
        return jsonify({"error": "admin only"}), 403
    db = get_db()
    rows = db.execute(
        "SELECT al.*, u.username FROM audit_logs al LEFT JOIN users u ON al.user_id=u.id ORDER BY al.timestamp DESC LIMIT 100"
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/users/<int:uid>/role", methods=["PUT"])
def set_role(uid):
    user = require_roles(request.headers.get("Authorization", ""), ["admin"])
    if not user:
        return jsonify({"error": "admin only"}), 403
    data = request.get_json()
    new_role = data.get("role")
    if new_role not in ("student", "advisor", "admin"):
        return jsonify({"error": "invalid role"}), 400
    db = get_db()
    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
    db.commit()
    db.close()
    audit(user["id"], "ROLE_CHANGED", f"target={uid} new_role={new_role}")
    return jsonify({"message": "role updated"})


if __name__ == "__main__":
    init_db()
    start_event_worker()
    print("🎓 SDU AI Agent starting...")
    print("Frontend: open frontend/index.html in your browser")
    print("Backend:  http://localhost:8080")
    app.run(port=8080, debug=True)
