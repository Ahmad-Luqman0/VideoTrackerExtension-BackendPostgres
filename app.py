from flask import Flask, request, jsonify
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone
import os
from flask_cors import CORS
import re
import secrets
import json

app = Flask(__name__)
# Configure CORS to allow requests from Chrome extension and handle Private Network Access
CORS(
    app,
    resources={
        r"/*": {
            "origins": "*",
            "allow_headers": ["Content-Type"],
            "expose_headers": ["*"],
            "supports_credentials": False,
        }
    },
)


# Add headers for Chrome Private Network Access
@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS")
    response.headers.add("Access-Control-Allow-Private-Network", "true")
    return response


DATABASE_URL = (
    os.getenv("DATABASE_URL")
    or "postgresql://postgres.nhmrfxrpwjeufaxgukes:luqmanahmad1@aws-1-ap-southeast-2.pooler.supabase.com:6543/postgres"
)


def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is required")
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True  # Enable autocommit to prevent transaction rollback issues
    return conn


def validate_username(username):
    """
    Validate username:
    - 8-15 characters
    - At least one number
    - At least one special character (only . - _ allowed)
    - Only letters, numbers, and .-_ allowed
    """
    if not username:
        return False, "Username is required"
    if not (8 <= len(username) <= 15):
        return False, "Username must be 8-15 characters long"
    if not re.search(r"[0-9]", username):
        return False, "Username must contain at least one number"
    if not re.search(r"[.\-_]", username):
        return False, "Username must contain at least one special character (., -, _)"
    if not re.match(r"^[A-Za-z0-9.\-_]+$", username):
        return (
            False,
            "Username can only contain letters, numbers, period, hyphen, and underscore",
        )
    return True, "Valid username"


def validate_password(password):
    """
    Validate password:
    - At least 8 characters
    - At least one uppercase letter
    - At least one number
    - At least one special character
    """
    if not password:
        return False, "Password is required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character"
    return True, "Valid password"


def generate_session_id():
    """Generate a secure random session ID"""
    return secrets.token_urlsafe(32)


@app.route("/", methods=["GET"])
def home():
    return "BackEnd Running  :)"


# Handle OPTIONS preflight requests for CORS
@app.route("/<path:path>", methods=["OPTIONS"])
def handle_options(path):
    response = jsonify({"status": "ok"})
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS")
    response.headers.add("Access-Control-Allow-Private-Network", "true")
    return response, 200


# --- REGISTER (create new user with duplicate prevention, UserTypes, and all fields) ---
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    phone = data.get("phone")
    user_type_id = data.get("userTypeId")
    print("[REGISTER] Incoming data:", data)

    # Validate input
    if not name or not email or not password or not user_type_id:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Name, email, password, and userTypeId are required",
                }
            ),
            400,
        )

    # Validate password format
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return jsonify({"success": False, "error": error_msg}), 400

    try:
        conn = get_conn()
        cur = conn.cursor()
        # Check for duplicate email
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            cur.close()
            conn.close()
            print("[REGISTER] Duplicate email:", email)
            return jsonify({"success": False, "error": "Email already exists"}), 409

        # Check userTypeId exists
        cur.execute("SELECT id FROM usertypes WHERE id = %s", (user_type_id,))
        user_type_row = cur.fetchone()
        if not user_type_row:
            cur.close()
            conn.close()
            print("[REGISTER] Invalid userTypeId:", user_type_id)
            return jsonify({"success": False, "error": "Invalid userTypeId"}), 400

        try:
            cur.execute(
                "INSERT INTO users (name, email, password, phone, usertype_id) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (name, email, password, phone, user_type_id),
            )
            user_id = cur.fetchone()[0]
            conn.commit()
            print(f"[REGISTER] User created: id={user_id}, email={email}")
        except Exception as insert_err:
            print(f"[REGISTER] Insert error: {insert_err}")
            raise
        cur.close()
        conn.close()
        return jsonify({"success": True, "user_id": user_id})
    except Exception as e:
        import traceback

        print("[REGISTER] Exception:", str(e))
        traceback.print_exc()
        return (
            jsonify(
                {"success": False, "error": "Failed to create user", "detail": str(e)}
            ),
            500,
        )


# --- GET USER TYPES (for registration dropdown) ---
@app.route("/usertypes", methods=["GET"])
def get_usertypes():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM usertypes WHERE active = true")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        user_types = [{"id": row[0], "name": row[1]} for row in rows]
        return jsonify({"userTypes": user_types})
    except Exception as e:
        return jsonify({"userTypes": [], "error": str(e)}), 500


# --- LOGIN (create new session for the user, log to UserActivities) ---
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    print("[LOGIN] Incoming data:", data)

    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        print(
            f"[LOGIN] Executing: SELECT id FROM users WHERE email = %s AND password = %s with email={email}"
        )
        cur.execute(
            "SELECT id FROM users WHERE email = %s AND password = %s",
            (email, password),
        )
        row = cur.fetchone()
        print(f"[LOGIN] Query result: {row}")
        if not row:
            cur.close()
            conn.close()
            print(f"[LOGIN] Invalid email or password for email={email}")
            return (
                jsonify({"success": False, "error": "Invalid email or password."}),
                401,
            )

        user_id = row["id"]
        session_id = generate_session_id()
        starttime = datetime.now(timezone.utc)
        cur.execute(
            "INSERT INTO sessions (id, user_id, starttime) VALUES (%s, %s, %s)",
            (session_id, user_id, starttime),
        )
        # Log login activity
        cur.execute(
            "INSERT INTO useractivities (userid, activitytype, timestamp, created_at, updated_at) VALUES (%s, %s, %s, %s, %s)",
            (user_id, "login", starttime, starttime, starttime),
        )
        conn.commit()
        cur.close()
        conn.close()
        print(f"[LOGIN] Success: user_id={user_id}, session_id={session_id}")
        return jsonify({"success": True, "session_id": session_id})
    except Exception as e:
        import traceback

        print("[LOGIN] Exception:", str(e))
        traceback.print_exc()
        return (
            jsonify({"success": False, "error": "Login failed", "detail": str(e)}),
            500,
        )


# --- LOGOUT (set endtime + duration on last session, log to UserActivities) ---
@app.route("/logout", methods=["POST"])
def logout():
    data = request.json
    session_id = data.get("session_id")
    if not session_id:
        return jsonify({"success": False, "error": "Missing session_id"}), 400

    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id, starttime, total_videos_watched FROM sessions WHERE id = %s",
            (session_id,),
        )
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Session not found"}), 404

        user_id = row[0]
        starttime = row[1]
        total_videos = row[2]
        endtime = datetime.now(timezone.utc)
        duration = None
        if starttime:
            duration = (endtime - starttime).total_seconds()

        cur.execute(
            "UPDATE sessions SET endtime = %s, duration = %s WHERE id = %s",
            (endtime, duration, session_id),
        )
        # Log logout activity
        cur.execute(
            "INSERT INTO useractivities (userid, activitytype, timestamp, created_at, updated_at) VALUES (%s, %s, %s, %s, %s)",
            (user_id, "logout", endtime, endtime, endtime),
        )
        conn.commit()
        cur.close()
        conn.close()

        return jsonify(
            {
                "success": True,
                "endtime": endtime.isoformat(),
                "duration": duration,
                "total_videos_watched": total_videos,
            }
        )
    except Exception as e:
        return (
            jsonify({"success": False, "error": "Logout failed", "detail": str(e)}),
            500,
        )


# --- LOG VIDEO (merge keys + speeds instead of overwrite, add loopTime) ---
@app.route("/log_video", methods=["POST"])
def log_video():
    print("=" * 80)
    print("[LOG_VIDEO] REQUEST RECEIVED!")
    print("=" * 80)
    data = request.json
    print(f"[LOG_VIDEO] Incoming data: {data}")
    session_id = data.get("session_id")

    if not session_id:
        print("[LOG_VIDEO] ERROR: Missing session_id")
        return jsonify({"success": False, "error": "Missing session_id"}), 400

    # Session ID is now a string, no need to convert to ObjectId

    # Handle keys - if null/None, keep as empty list for processing
    keys = data.get("keys")
    if keys is None:
        keys = []
    elif not isinstance(keys, list):
        keys = [keys] if keys else []

    # Always store speeds as list
    speeds = data.get("speeds")
    if not isinstance(speeds, list):
        speeds = [speeds] if speeds else []

    # Get sound muted state as simple boolean (yes/no)
    sound_muted = data.get("soundMuted", False)  # Default to False (not muted)
    # Convert to "yes" if muted, "no" if not muted
    sound_muted_status = "yes" if sound_muted else "no"

    video_id = data.get("videoId")
    duration = float(data.get("duration", 0))
    watched = int(data.get("watched", 0))
    loop_time = int(data.get("loopTime", 0))  # <-- NEW
    status = data.get("status", "Not Watched")

    try:
        conn = get_conn()
        cur = conn.cursor()  # Use regular cursor instead of DictCursor

        # confirm session exists
        cur.execute("SELECT id FROM sessions WHERE id = %s", (session_id,))
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Session not found"}), 404

        # Log incoming data for debugging
        print(
            f"[LOG_VIDEO] video_id: {video_id[:50]}..., watched: {watched}, loop_time: {loop_time}, status: {status}, speeds: {speeds}"
        )

        # Use UPSERT to avoid race conditions
        # Track if this is a new video insert or an update
        # Only update watched/loop_time if new values are greater (accumulate)
        cur.execute(
            """
            INSERT INTO videos (session_id, video_id, duration, watched, loop_time, status, sound_muted)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (session_id, video_id) 
            DO UPDATE SET 
                duration = EXCLUDED.duration,
                watched = GREATEST(videos.watched, EXCLUDED.watched),
                loop_time = GREATEST(videos.loop_time, EXCLUDED.loop_time),
                status = EXCLUDED.status,
                sound_muted = EXCLUDED.sound_muted
            RETURNING id, (xmax = 0) AS is_new_video
            """,
            (
                session_id,
                video_id,
                duration,
                watched,
                loop_time,
                status,
                sound_muted_status,
            ),
        )
        result = cur.fetchone()
        vid = result[0]
        is_new_video = result[1]

        print(f"[LOG_VIDEO] Inserted/Updated video_id={vid}, is_new={is_new_video}")

        # If this is a new video, increment total_videos_watched
        if is_new_video:
            cur.execute(
                "UPDATE sessions SET total_videos_watched = total_videos_watched + 1 WHERE id = %s",
                (session_id,),
            )

        # Insert keys (if empty list, insert NULL)
        if not keys or len(keys) == 0:
            try:
                cur.execute(
                    "INSERT INTO video_keys (video_id, key_value) VALUES (%s, %s) ON CONFLICT (video_id, key_value) DO NOTHING",
                    (vid, None),
                )
            except Exception:
                pass
        else:
            for k in keys:
                try:
                    cur.execute(
                        "INSERT INTO video_keys (video_id, key_value) VALUES (%s, %s) ON CONFLICT (video_id, key_value) DO NOTHING",
                        (vid, k),
                    )
                except Exception:
                    # ignore individual key insert errors
                    pass
            # --- RETROACTIVE KEY ASSIGNMENT ---
            # Assign this key to all previous videos in this session that have NULL key
            try:
                cur.execute(
                    "SELECT v.id FROM videos v "
                    "LEFT JOIN video_keys vk ON v.id = vk.video_id "
                    "WHERE v.session_id = %s AND v.id <> %s AND vk.key_value IS NULL",
                    (session_id, vid),
                )
                prev_rows = cur.fetchall()
                for prev_row in prev_rows:
                    prev_vid = prev_row[0]
                    for k in keys:
                        # Remove NULL key if present
                        cur.execute(
                            "DELETE FROM video_keys WHERE video_id = %s AND key_value IS NULL",
                            (prev_vid,),
                        )
                        # Insert the new key
                        cur.execute(
                            "INSERT INTO video_keys (video_id, key_value) VALUES (%s, %s) ON CONFLICT (video_id, key_value) DO NOTHING",
                            (prev_vid, k),
                        )
            except Exception as e:
                print(f"[LOG_VIDEO]  Retroactive key assignment failed: {e}")

        # Insert speeds (always insert at least one default speed)
        if not speeds or len(speeds) == 0:
            speeds = [1.0]  # Default speed

        for s in speeds:
            try:
                # Convert speed string like "1x", "1.5x" to float
                if isinstance(s, str):
                    speed_val = float(s.replace("x", "").replace("X", ""))
                else:
                    speed_val = float(s)

                cur.execute(
                    "INSERT INTO video_speeds (video_id, speed_value) VALUES (%s, %s) ON CONFLICT (video_id, speed_value) DO NOTHING",
                    (vid, speed_val),
                )
            except Exception as e:
                # Insert default 1.0 if conversion fails
                try:
                    cur.execute(
                        "INSERT INTO video_speeds (video_id, speed_value) VALUES (%s, %s) ON CONFLICT (video_id, speed_value) DO NOTHING",
                        (vid, 1.0),
                    )
                except Exception:
                    pass

        conn.commit()
        print(f"[LOG_VIDEO]  COMMIT SUCCESSFUL for video_id={vid}")

        cur.close()
        conn.close()

        # VERIFICATION: Use NEW connection to check if video persists
        try:
            import time

            time.sleep(0.5)  # Wait 500ms for consistency
            verify_conn = get_conn()
            verification_cur = verify_conn.cursor()
            verification_cur.execute(
                "SELECT watched, loop_time FROM videos WHERE id = %s", (vid,)
            )
            verify_result = verification_cur.fetchone()
            if verify_result:
                print(
                    f"[LOG_VIDEO]  VERIFIED: Video {vid} exists in DB with watched={verify_result[0]}, loop_time={verify_result[1]}"
                )
            else:
                print(f"[LOG_VIDEO]  ERROR: Video {vid} NOT FOUND after commit!")
            verification_cur.close()
            verify_conn.close()
        except Exception as ve:
            print(f"[LOG_VIDEO]  Verification failed: {ve}")

        video_entry = {
            "videoId": video_id,
            "duration": duration,
            "watched": watched,
            "loopTime": loop_time,
            "status": status,
            "keys": keys,
            "speeds": speeds,
            "soundMuted": sound_muted_status,
        }
        print(f"[LOG_VIDEO]  FUNCTION COMPLETING SUCCESSFULLY for video_id={vid}")
        return jsonify({"success": True, "video": video_entry})
    except Exception as e:
        print(f"[LOG_VIDEO]  EXCEPTION OCCURRED: {str(e)}")
        print(f"[LOG_VIDEO] Exception type: {type(e).__name__}")
        import traceback

        traceback.print_exc()
        try:
            if "conn" in locals():
                conn.rollback()
                conn.close()
        except:
            pass
        return (
            jsonify(
                {"success": False, "error": "Failed to log video", "detail": str(e)}
            ),
            500,
        )


# --- LOG INACTIVITY (push inactivity events into session) ---
@app.route("/log_inactivity", methods=["POST"])
def log_inactivity():
    data = request.json
    session_id = data.get("session_id")
    if not session_id:
        return jsonify({"success": False, "error": "Missing session_id"}), 400

    # Session ID is now a string, no need to convert to ObjectId

    inactivity_entry = {
        "starttime": data.get("starttime"),
        "endtime": data.get("endtime"),
        "duration": data.get("duration"),
        "type": data.get("type"),
    }

    try:
        conn = get_conn()
        cur = conn.cursor()
        # ensure session exists
        cur.execute("SELECT id, starttime FROM sessions WHERE id = %s", (session_id,))
        srow = cur.fetchone()
        if not srow:
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Session not found"}), 404

        # Insert inactivity
        cur.execute(
            "INSERT INTO inactivity (session_id, starttime, endtime, duration, type) VALUES (%s,%s,%s,%s,%s)",
            (
                session_id,
                inactivity_entry.get("starttime"),
                inactivity_entry.get("endtime"),
                inactivity_entry.get("duration"),
                inactivity_entry.get("type"),
            ),
        )

        # Check duration to decide split
        try:
            inactivity_duration = float(inactivity_entry.get("duration", 0) or 0)
        except Exception:
            inactivity_duration = 0

        new_session_id = None
        if inactivity_duration > 180:
            # End current session
            cur.execute("SELECT starttime FROM sessions WHERE id = %s", (session_id,))
            starttime = cur.fetchone()[0]
            endtime = datetime.now(timezone.utc)
            duration = None
            if starttime:
                duration = (endtime - starttime).total_seconds()

            cur.execute(
                "UPDATE sessions SET endtime = %s, duration = %s WHERE id = %s",
                (endtime, duration, session_id),
            )

            # Create a new session that starts at endtime
            new_session_id = generate_session_id()
            cur.execute(
                "INSERT INTO sessions (id, user_id, starttime) SELECT %s, user_id, %s FROM sessions WHERE id = %s",
                (new_session_id, endtime, session_id),
            )

        conn.commit()
        cur.close()
        conn.close()

        resp = {"success": True, "inactivity": inactivity_entry}
        if new_session_id:
            resp.update({"action": "session_split", "new_session_id": new_session_id})
        return jsonify(resp)
    except Exception as e:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Failed to log inactivity",
                    "detail": str(e),
                }
            ),
            500,
        )


# --- QUEUES API ---
@app.route("/queues", methods=["POST"])
def create_queue():
    data = request.json or {}
    # Require session_id to link queue to a session
    session_id = data.get("session_id")
    name = data.get("name")
    main_queue = data.get("main_queue")
    main_queue_count = int(data.get("main_queue_count", 0) or 0)
    subqueues = data.get("subqueues", [])
    # subqueue_counts can be object or list of {name,count}
    subqueue_counts = data.get("subqueue_counts", {})

    if not session_id or not name:
        return (
            jsonify({"success": False, "error": "Missing session_id or queue name"}),
            400,
        )

    try:
        conn = get_conn()
        cur = conn.cursor()
        # Ensure session exists
        cur.execute("SELECT id FROM sessions WHERE id = %s", (session_id,))
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Session not found"}), 404

        # Normalize subqueue_counts to JSON object
        if isinstance(subqueue_counts, list):
            obj = {}
            for item in subqueue_counts:
                try:
                    obj[item.get("name")] = int(item.get("count", 0) or 0)
                except Exception:
                    pass
            subqueue_counts = obj

        cur.execute(
            """
            INSERT INTO queues (name, session_id, main_queue, main_queue_count, subqueues, subqueue_counts)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (session_id, name) DO UPDATE SET
                main_queue = EXCLUDED.main_queue,
                main_queue_count = GREATEST(queues.main_queue_count, EXCLUDED.main_queue_count),
                subqueues = EXCLUDED.subqueues,
                subqueue_counts = EXCLUDED.subqueue_counts,
                updated_at = NOW()
            RETURNING id
            """,
            (
                name,
                session_id,
                main_queue,
                main_queue_count,
                json.dumps(subqueues),
                json.dumps(subqueue_counts),
            ),
        )
        queue_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"success": True, "queue_id": queue_id, "name": name})
    except Exception as e:
        return (
            jsonify(
                {"success": False, "error": "Failed to create queue", "detail": str(e)}
            ),
            500,
        )


@app.route("/queues", methods=["GET"])
def list_queues():
    try:
        conn = get_conn()
        cur = conn.cursor()
        # Allow optional filtering by session_id
        session_id = request.args.get("session_id")
        if session_id:
            cur.execute(
                "SELECT id, name, session_id, main_queue, main_queue_count, subqueues, subqueue_counts, active, created_at FROM queues WHERE session_id = %s ORDER BY id DESC",
                (session_id,),
            )
        else:
            cur.execute(
                "SELECT id, name, session_id, main_queue, main_queue_count, subqueues, subqueue_counts, active, created_at FROM queues ORDER BY id DESC"
            )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        queues = []
        for r in rows:
            queues.append(
                {
                    "id": r[0],
                    "name": r[1],
                    "session_id": r[2],
                    "main_queue": r[3],
                    "main_queue_count": r[4],
                    "subqueues": json.loads(r[5]) if r[5] else [],
                    "subqueue_counts": json.loads(r[6]) if r[6] else {},
                    "active": r[7],
                    "created_at": r[8].isoformat() if r[8] else None,
                }
            )
        return jsonify({"success": True, "queues": queues})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# --- CARDS API ---
def _adjust_queue_counts(cur, queue_id, metadata, delta=1):
    """Adjust main_queue_count and subqueue_counts for a queue by delta (+1 or -1)."""
    if queue_id is None:
        return
    # Lock queue row
    cur.execute(
        "SELECT main_queue_count, subqueue_counts FROM queues WHERE id = %s FOR UPDATE",
        (queue_id,),
    )
    row = cur.fetchone()
    if not row:
        return
    main_count = row[0] or 0
    sub_counts_json = row[1]
    try:
        sub_counts = json.loads(sub_counts_json) if sub_counts_json else {}
    except Exception:
        sub_counts = {}

    main_count = max(0, int(main_count) + int(delta))

    # If metadata contains explicit subqueue name, adjust that count
    if metadata and isinstance(metadata, dict):
        subname = (
            metadata.get("subqueue") or metadata.get("sub_queue") or metadata.get("sub")
        )
        if subname:
            try:
                current = int(sub_counts.get(subname, 0) or 0)
            except Exception:
                current = 0
            current = max(0, current + int(delta))
            sub_counts[subname] = current

    cur.execute(
        "UPDATE queues SET main_queue_count = %s, subqueue_counts = %s, updated_at = NOW() WHERE id = %s",
        (main_count, json.dumps(sub_counts), queue_id),
    )


@app.route("/cards", methods=["POST"])
def add_card():
    data = request.json or {}
    session_id = data.get("session_id")
    card_id = data.get("card_id")
    status = data.get("status")
    queue_id = data.get("queue_id")
    metadata = data.get("metadata")

    if not session_id or not card_id or not status or not queue_id:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "session_id, card_id, status and queue_id are required",
                }
            ),
            400,
        )

    if status not in ("accept", "reject"):
        return jsonify({"success": False, "error": "Invalid status value"}), 400

    try:
        conn = get_conn()
        cur = conn.cursor()

        # ensure session exists
        cur.execute("SELECT id FROM sessions WHERE id = %s", (session_id,))
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Session not found"}), 404

        # ensure queue exists and belongs to session
        cur.execute(
            "SELECT id FROM queues WHERE id = %s AND session_id = %s",
            (queue_id, session_id),
        )
        if not cur.fetchone():
            cur.close()
            conn.close()
            return (
                jsonify(
                    {"success": False, "error": "Queue not found for this session"}
                ),
                404,
            )

        # check existing card
        cur.execute(
            "SELECT id, queue_id, metadata FROM cards WHERE session_id = %s AND card_id = %s",
            (session_id, card_id),
        )
        existing = cur.fetchone()

        if existing:
            existing_id = existing[0]
            old_queue_id = existing[1]
            old_metadata_json = existing[2]
            old_metadata = None
            try:
                old_metadata = (
                    json.loads(old_metadata_json) if old_metadata_json else None
                )
            except Exception:
                old_metadata = None

            cur.execute(
                "UPDATE cards SET status = %s, queue_id = %s, metadata = %s, updated_at = NOW() WHERE id = %s RETURNING id",
                (
                    status,
                    queue_id,
                    json.dumps(metadata) if metadata is not None else None,
                    existing_id,
                ),
            )
            card_db_id = cur.fetchone()[0]

            # If queue changed, adjust counts
            if old_queue_id != queue_id:
                _adjust_queue_counts(cur, old_queue_id, old_metadata, delta=-1)
                _adjust_queue_counts(cur, queue_id, metadata, delta=1)

        else:
            cur.execute(
                "INSERT INTO cards (session_id, card_id, status, queue_id, metadata) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                (
                    session_id,
                    card_id,
                    status,
                    queue_id,
                    json.dumps(metadata) if metadata is not None else None,
                ),
            )
            card_db_id = cur.fetchone()[0]
            # New card -> increment queue counts
            _adjust_queue_counts(cur, queue_id, metadata, delta=1)

        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"success": True, "card_id": card_db_id})
    except Exception as e:
        return (
            jsonify(
                {"success": False, "error": "Failed to add card", "detail": str(e)}
            ),
            500,
        )


@app.route("/cards/bulk", methods=["POST"])
def add_cards_bulk():
    data = request.json or {}
    cards = data.get("cards")
    if not cards or not isinstance(cards, list):
        return jsonify({"success": False, "error": "cards list required"}), 400

    results = []
    try:
        conn = get_conn()
        cur = conn.cursor()
        for c in cards:
            session_id = c.get("session_id")
            card_id = c.get("card_id")
            status = c.get("status")
            queue_id = c.get("queue_id")
            metadata = c.get("metadata")

            if not session_id or not card_id or not status or not queue_id:
                results.append(
                    {"card_id": card_id, "success": False, "error": "missing fields"}
                )
                continue

            try:
                # ensure session and queue exist
                cur.execute("SELECT id FROM sessions WHERE id = %s", (session_id,))
                if not cur.fetchone():
                    results.append(
                        {
                            "card_id": card_id,
                            "success": False,
                            "error": "session not found",
                        }
                    )
                    continue
                cur.execute(
                    "SELECT id FROM queues WHERE id = %s AND session_id = %s",
                    (queue_id, session_id),
                )
                if not cur.fetchone():
                    results.append(
                        {
                            "card_id": card_id,
                            "success": False,
                            "error": "queue not found for session",
                        }
                    )
                    continue

                # check existing
                cur.execute(
                    "SELECT id, queue_id, metadata FROM cards WHERE session_id = %s AND card_id = %s",
                    (session_id, card_id),
                )
                existing = cur.fetchone()
                if existing:
                    eid = existing[0]
                    old_queue_id = existing[1]
                    old_metadata_json = existing[2]
                    old_metadata = None
                    try:
                        old_metadata = (
                            json.loads(old_metadata_json) if old_metadata_json else None
                        )
                    except Exception:
                        old_metadata = None

                    cur.execute(
                        "UPDATE cards SET status = %s, queue_id = %s, metadata = %s, updated_at = NOW() WHERE id = %s RETURNING id",
                        (
                            status,
                            queue_id,
                            json.dumps(metadata) if metadata is not None else None,
                            eid,
                        ),
                    )
                    cid = cur.fetchone()[0]
                    if old_queue_id != queue_id:
                        _adjust_queue_counts(cur, old_queue_id, old_metadata, delta=-1)
                        _adjust_queue_counts(cur, queue_id, metadata, delta=1)
                    results.append(
                        {"card_id": card_id, "success": True, "card_db_id": cid}
                    )
                else:
                    cur.execute(
                        "INSERT INTO cards (session_id, card_id, status, queue_id, metadata) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                        (
                            session_id,
                            card_id,
                            status,
                            queue_id,
                            json.dumps(metadata) if metadata is not None else None,
                        ),
                    )
                    cid = cur.fetchone()[0]
                    _adjust_queue_counts(cur, queue_id, metadata, delta=1)
                    results.append(
                        {"card_id": card_id, "success": True, "card_db_id": cid}
                    )
            except Exception as e:
                results.append({"card_id": card_id, "success": False, "error": str(e)})

        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return (
            jsonify(
                {"success": False, "error": "Bulk insert failed", "detail": str(e)}
            ),
            500,
        )


if __name__ == "__main__":
    import os

    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
