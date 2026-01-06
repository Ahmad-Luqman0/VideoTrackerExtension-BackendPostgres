from flask import Flask, request, jsonify
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone
import os
from flask_cors import CORS
import re
import secrets
import json
import hashlib

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
            # Hash the password using SHA-256 before storing
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            
            cur.execute(
                "INSERT INTO users (name, email, password, phone, usertype_id) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (name, email, hashed_password, phone, user_type_id),
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
            f"[LOGIN] Executing: SELECT id, password FROM users WHERE email = %s with email={email}"
        )
        # First, get the user by email only
        cur.execute(
            "SELECT id, password FROM users WHERE email = %s",
            (email,),
        )
        row = cur.fetchone()
        print(f"[LOGIN] Query result: {row}")
        
        if not row:
            cur.close()
            conn.close()
            print(f"[LOGIN] User not found for email={email}")
            return (
                jsonify({"success": False, "error": "Invalid email or password."}),
                401,
            )
        
        # Verify the password using SHA-256 hash comparison
        stored_password = row["password"]
        hashed_input_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        if hashed_input_password != stored_password:
            cur.close()
            conn.close()
            print(f"[LOGIN] Invalid password for email={email}")
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
    print("[QUEUES] Incoming payload:", data)
    # Require session_id to link queue to a session
    session_id = data.get("session_id")
    name = data.get("name")
    main_queue = data.get("main_queue")
    main_queue_count = int(data.get("main_queue_count", 0) or 0)
    subqueues = data.get("subqueues", [])
    # subqueue_counts can be object or list of {name,count}
    subqueue_counts = data.get("subqueue_counts", {})
    selected_subqueue = data.get("selected_subqueue")
    queue_count_old = data.get("queue_count_old")
    queue_count_new = data.get("queue_count_new")
    subqueue_count_old = data.get("subqueue_count_old")
    subqueue_count_new = data.get("subqueue_count_new")

    if not session_id or not name:
        print("[QUEUES] Missing session_id or queue name")
        return (
            jsonify({"success": False, "error": "Missing session_id or queue name"}),
            400,
        )

    # Validation: only allow a known set of main queues (countries / global aliases)
    allowed_main_queues = {
        "brazil",
        "indonesia",
        "mexico",
        "colombia",
        "argentina",
        "pakistan",
        "egypt",
        "turkey",
        "peru",
        "saudi arabia",
        "jordan",
        "iraq",
        "america",
        "global",
        "usa",
        "us",
        "uk",
        "united states",
        "canada",
        "china",
        "japan",
        "korea",
        "thailand",
        "vietnam",
        "philippines",
        "malaysia",
        "singapore",
        "australia",
        "russia",
        "france",
        "germany",
        "spain",
        "italy",
        "ksa",
        "sa",
        "uae",
        "nz",
    }

    def is_allowed_main_queue(s):
        try:
            return bool(s and s.strip().lower() in allowed_main_queues)
        except Exception:
            return False

    # If a subqueue-like name is provided (contains dash or special tokens) then a main_queue must be present
    looks_like_subqueue = bool(name and re.search(r"[-_/]", name))

    if main_queue:
        if not is_allowed_main_queue(main_queue):
            print(f"[QUEUES] Invalid main_queue value: {main_queue}")
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Invalid main_queue: must be one of allowed country/main names",
                    }
                ),
                400,
            )

    # Reject attempts to use a subqueue name as the main_queue (e.g., frontend fallback used subqueue of the same name)
    if name and main_queue and name == main_queue and looks_like_subqueue:
        print(f"[QUEUES] Refusing to treat subqueue name as main_queue: name={name}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Invalid request: provided queue name looks like a subqueue. Provide the main_queue (country) separately.",
                }
            ),
            400,
        )

    # If the payload appears to be describing a subqueue (name contains -) ensure main_queue is provided
    if looks_like_subqueue and not main_queue:
        print(f"[QUEUES] Subqueue payload missing main_queue: name={name}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Subqueue payload requires a valid main_queue (country name)",
                }
            ),
            400,
        )

    try:
        conn = get_conn()
        cur = conn.cursor()
        # Ensure session exists
        cur.execute("SELECT id FROM sessions WHERE id = %s", (session_id,))
        if not cur.fetchone():
            print(f"[QUEUES] Session not found for session_id={session_id}")
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Session not found"}), 404
        # If the payload represents a subqueue (name != main_queue) and a main_queue is provided,
        # update the main_queue row's subqueue_counts instead of creating a separate queue row for the subqueue.
        try:
            if main_queue and name and name != main_queue:
                # Lock main_queue row for update (create it if missing)
                cur.execute(
                    "SELECT id, subqueue_counts FROM queues WHERE session_id = %s AND name = %s FOR UPDATE",
                    (session_id, main_queue),
                )
                mrow = cur.fetchone()
                if mrow:
                    main_id = mrow[0]
                    existing_subcounts = mrow[1]
                    try:
                        existing_subcounts = (
                            json.loads(existing_subcounts) if existing_subcounts else {}
                        )
                    except Exception:
                        existing_subcounts = {}
                else:
                    # Create a main queue row if it doesn't exist
                    cur.execute(
                        "INSERT INTO queues (name, session_id, main_queue, main_queue_count, subqueues, subqueue_counts, selected_subqueue, queue_count_old, queue_count_new, subqueue_count_old, subqueue_count_new) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                        (
                            main_queue,
                            session_id,
                            main_queue,
                            main_queue_count,
                            json.dumps(subqueues),
                            json.dumps({}),
                            None,
                            main_queue_count,
                            None,
                            None,
                            None,
                        ),
                    )
                    main_id = cur.fetchone()[0]
                    existing_subcounts = {}

                # Determine subqueue count to write (prefer explicit subqueue_count_old, then queue_count_old)
                try:
                    sub_old = int(subqueue_count_old or queue_count_old or 0)
                except Exception:
                    sub_old = 0

                # Update the main queue's subqueue_counts and audit fields
                existing_subcounts[name] = sub_old
                cur.execute(
                    "UPDATE queues SET subqueue_counts = %s, selected_subqueue = %s, subqueue_count_old = %s, subqueue_count_new = %s, updated_at = NOW() WHERE id = %s",
                    (json.dumps(existing_subcounts), name, sub_old, None, main_id),
                )
                conn.commit()
                cur.close()
                conn.close()
                print(
                    f"[QUEUES] Updated main queue {main_queue} with subqueue {name} count={sub_old}"
                )
                return jsonify(
                    {"success": True, "name": main_queue, "queue_id": main_id}
                )
        except Exception as e:
            print(f"[QUEUES] Exception handling subqueue-as-update: {e}")
            import traceback

            traceback.print_exc()
            # fall through to normal insert handling on unexpected errors

        # Normalize subqueue_counts to JSON object
        if isinstance(subqueue_counts, list):
            obj = {}
            for item in subqueue_counts:
                try:
                    obj[item.get("name")] = int(item.get("count", 0) or 0)
                except Exception:
                    pass
            subqueue_counts = obj

        # Ensure `subqueues` array reflects the keys present in subqueue_counts
        try:
            if isinstance(subqueue_counts, dict):
                # preserve insertion order where possible
                subqueues = list(subqueue_counts.keys())
            else:
                subqueues = subqueues if subqueues is not None else []
        except Exception:
            subqueues = subqueues if subqueues is not None else []

        print(
            f"[QUEUES] Inserting queue: name={name}, session_id={session_id}, main_queue={main_queue}, main_queue_count={main_queue_count}, subqueues={subqueues}, subqueue_counts={subqueue_counts}"
        )
        try:
            cur.execute(
                """
                INSERT INTO queues (name, session_id, main_queue, main_queue_count, subqueues, subqueue_counts, selected_subqueue, queue_count_old, queue_count_new, subqueue_count_old, subqueue_count_new)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (session_id, name) DO UPDATE SET
                    main_queue = EXCLUDED.main_queue,
                    main_queue_count = GREATEST(queues.main_queue_count, EXCLUDED.main_queue_count),
                    subqueues = CASE WHEN EXCLUDED.subqueues IS NOT NULL AND EXCLUDED.subqueues != '[]'::jsonb THEN EXCLUDED.subqueues ELSE queues.subqueues END,
                    subqueue_counts = CASE WHEN EXCLUDED.subqueue_counts IS NOT NULL AND EXCLUDED.subqueue_counts != '{}'::jsonb THEN EXCLUDED.subqueue_counts ELSE queues.subqueue_counts END,
                    selected_subqueue = COALESCE(EXCLUDED.selected_subqueue, queues.selected_subqueue),
                    queue_count_old = COALESCE(EXCLUDED.queue_count_old, queues.queue_count_old),
                    queue_count_new = COALESCE(EXCLUDED.queue_count_new, queues.queue_count_new),
                    subqueue_count_old = COALESCE(EXCLUDED.subqueue_count_old, queues.subqueue_count_old),
                    subqueue_count_new = COALESCE(EXCLUDED.subqueue_count_new, queues.subqueue_count_new),
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
                    selected_subqueue,
                    queue_count_old,
                    queue_count_new,
                    subqueue_count_old,
                    subqueue_count_new,
                ),
            )
            queue_id = cur.fetchone()[0]
            conn.commit()
            print(f"[QUEUES] Queue inserted/updated: id={queue_id}")
            cur.close()
            conn.close()
            return jsonify({"success": True, "queue_id": queue_id, "name": name})
        except Exception as e:
            print(f"[QUEUES] Exception during insert/update: {e}")
            import traceback

            traceback.print_exc()
            raise
    except Exception as e:
        print(f"[QUEUES] Outer exception: {e}")
        import traceback

        traceback.print_exc()
        return (
            jsonify(
                {"success": False, "error": "Failed to create queue", "detail": str(e)}
            ),
            500,
        )


@app.route("/queues", methods=["GET"])
def list_queues():
    try:
        print("[QUEUES][DEBUG] Incoming GET /queues request")
        print(f"[QUEUES][DEBUG] Query params: {request.args}")
        conn = get_conn()
        cur = conn.cursor()
        session_id = request.args.get("session_id")
        if session_id:
            print(f"[QUEUES][DEBUG] Filtering by session_id: {session_id}")
            sql = "SELECT id, name, session_id, main_queue, main_queue_count, subqueues, subqueue_counts, selected_subqueue, queue_count_old, queue_count_new, subqueue_count_old, subqueue_count_new, active, created_at FROM queues WHERE session_id = %s ORDER BY id DESC"
            print(f"[QUEUES][DEBUG] SQL: {sql}")
            cur.execute(sql, (session_id,))
        else:
            sql = "SELECT id, name, session_id, main_queue, main_queue_count, subqueues, subqueue_counts, selected_subqueue, queue_count_old, queue_count_new, subqueue_count_old, subqueue_count_new, active, created_at FROM queues ORDER BY id DESC"
            print(f"[QUEUES][DEBUG] SQL: {sql}")
            cur.execute(sql)
        rows = cur.fetchall()
        print(f"[QUEUES][DEBUG] Rows fetched: {len(rows)}")
        queues = []
        for r in rows:
            print(f"[QUEUES][DEBUG] Row: {r}")
            # Fix: Only json.loads if value is a string
            subqueues_val = r[5]
            if isinstance(subqueues_val, str):
                try:
                    subqueues_val = json.loads(subqueues_val)
                except Exception:
                    subqueues_val = []
            elif not isinstance(subqueues_val, list):
                subqueues_val = []

            subqueue_counts_val = r[6]
            if isinstance(subqueue_counts_val, str):
                try:
                    subqueue_counts_val = json.loads(subqueue_counts_val)
                except Exception:
                    subqueue_counts_val = {}
            elif not isinstance(subqueue_counts_val, dict):
                subqueue_counts_val = {}

            # Map indices carefully after extended SELECT
            queues.append(
                {
                    "id": r[0],
                    "name": r[1],
                    "session_id": r[2],
                    "main_queue": r[3],
                    "main_queue_count": r[4],
                    "subqueues": subqueues_val,
                    "subqueue_counts": subqueue_counts_val,
                    "selected_subqueue": r[7],
                    "queue_count_old": r[8],
                    "queue_count_new": r[9],
                    "subqueue_count_old": r[10],
                    "subqueue_count_new": r[11],
                    "active": r[12],
                    "created_at": r[13].isoformat() if r[13] else None,
                }
            )
        cur.close()
        conn.close()
        print(f"[QUEUES][DEBUG] Returning {len(queues)} queues")
        return jsonify({"success": True, "queues": queues})
    except Exception as e:
        import traceback

        print(f"[QUEUES][ERROR] Exception: {e}")
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


# --- CARDS API ---
def _adjust_queue_counts(cur, queue_id, metadata, delta=1):
    """Adjust main_queue_count and subqueue_counts for a queue by delta (+1 or -1).

    Behavior:
    - Always update `queue_count_old` and `queue_count_new` when a card is submitted.
    - If `metadata` includes a `subqueue`, update that subqueue's count and set
      `subqueue_count_old` / `subqueue_count_new` accordingly.
    - If no `subqueue` is provided in `metadata`, attempt to infer a subqueue from the
      queue `name` (e.g. "brazil_subA") and update that. If no subqueue is inferable,
      preserve the existing `selected_subqueue` and `subqueue_count_new` (do not null them).
    """
    if queue_id is None:
        return

    # Lock queue row and read existing relevant fields (include name and main_queue)
    cur.execute(
        "SELECT name, main_queue, main_queue_count, subqueue_counts, selected_subqueue, queue_count_old, queue_count_new, subqueue_count_old, subqueue_count_new FROM queues WHERE id = %s FOR UPDATE",
        (queue_id,),
    )
    row = cur.fetchone()
    if not row:
        return

    queue_name = row[0]
    main_queue_field = row[1]
    main_count = row[2] or 0
    sub_counts_json = row[3]
    existing_selected = row[4]
    existing_queue_count_old = row[5]
    existing_queue_count_new = row[6]
    existing_subqueue_count_old = row[7]
    existing_subqueue_count_new = row[8]

    try:
        sub_counts = json.loads(sub_counts_json) if sub_counts_json else {}
    except Exception:
        sub_counts = {}

    # preserve old values
    # If frontend provided scraped counts and requested them to be used, honor them
    use_scraped = False
    try:
        if (
            metadata
            and isinstance(metadata, dict)
            and metadata.get("use_scraped_counts")
        ):
            use_scraped = True
    except Exception:
        use_scraped = False

    if (
        use_scraped
        and metadata.get("queue_count_old") is not None
        and metadata.get("queue_count_new") is not None
    ):
        try:
            prev_main_count = int(metadata.get("queue_count_old") or 0)
            main_count = int(metadata.get("queue_count_new") or prev_main_count)
        except Exception:
            prev_main_count = int(main_count or 0)
            main_count = max(0, int(prev_main_count) + int(delta))
    else:
        prev_main_count = int(main_count or 0)
        main_count = max(0, int(prev_main_count) + int(delta))

    # If metadata contains explicit subqueue name, adjust that count
    selected_subname = None
    prev_sub_count = 0
    if metadata and isinstance(metadata, dict):
        selected_subname = (
            metadata.get("subqueue") or metadata.get("sub_queue") or metadata.get("sub")
        )
        if selected_subname:
            # If frontend provided scraped subqueue counts and requested them to be used, honor them
            if (
                use_scraped
                and metadata.get("subqueue_count_old") is not None
                and metadata.get("subqueue_count_new") is not None
            ):
                try:
                    prev_sub_count = int(metadata.get("subqueue_count_old") or 0)
                    current = int(metadata.get("subqueue_count_new") or prev_sub_count)
                except Exception:
                    try:
                        current = int(sub_counts.get(selected_subname, 0) or 0)
                    except Exception:
                        current = 0
                    prev_sub_count = current
                    current = max(0, current + int(delta))
                sub_counts[selected_subname] = current
            else:
                try:
                    current = int(sub_counts.get(selected_subname, 0) or 0)
                except Exception:
                    current = 0
                prev_sub_count = current
                current = max(0, current + int(delta))
                sub_counts[selected_subname] = current

    # If no explicit subqueue in metadata, try to infer from the queue name (fallback IDs like 'brazil_subname')
    if not selected_subname:
        inferred = None
        try:
            if main_queue_field and queue_name and isinstance(queue_name, str):
                prefix = f"{main_queue_field}_"
                if queue_name.startswith(prefix):
                    inferred = queue_name[len(prefix) :]
            if (
                not inferred
                and queue_name
                and isinstance(queue_name, str)
                and "_" in queue_name
            ):
                inferred = queue_name.split("_", 1)[1]
        except Exception:
            inferred = None

        if inferred:
            selected_subname = inferred
            try:
                current = int(sub_counts.get(selected_subname, 0) or 0)
            except Exception:
                current = 0
            prev_sub_count = current
            current = max(0, current + int(delta))
            sub_counts[selected_subname] = current

        # If still no subqueue determined but there is an existing selected_subqueue,
        # update that subqueue's count (preserve selection name).
        if not selected_subname and existing_selected:
            try:
                current = int(sub_counts.get(existing_selected, 0) or 0)
            except Exception:
                current = 0
            prev_sub_count = current
            current = max(0, current + int(delta))
            sub_counts[existing_selected] = current
            # Set selected_subname so downstream logic treats it as adjusted
            selected_subname = existing_selected

    # Decide which 'old' audit fields to write:
    # - queue_count_old: write only if empty in DB; otherwise preserve existing value
    # - subqueue_count_old: if the selected subqueue changed (new != existing_selected), set it to the previous subqueue count; otherwise preserve existing value when present
    try:
        # Also maintain the `subqueues` array column (list of subqueue names) for easier display
        subqueues_list = list(sub_counts.keys())

        # Determine queue_count_old to write (preserve existing if present)
        queue_count_old_to_write = None
        try:
            if existing_queue_count_old is None:
                queue_count_old_to_write = int(prev_main_count or 0)
            else:
                queue_count_old_to_write = existing_queue_count_old
        except Exception:
            queue_count_old_to_write = int(prev_main_count or 0)

        # Determine subqueue_count_old to write
        subqueue_count_old_to_write = None
        try:
            if selected_subname:
                # If the selected subqueue changed compared to existing_selected, record the previous subqueue count
                if (not existing_selected) or (existing_selected != selected_subname):
                    subqueue_count_old_to_write = int(prev_sub_count or 0)
                else:
                    # preserve existing subqueue_count_old if present, otherwise set to prev_sub_count
                    if existing_subqueue_count_old is None:
                        subqueue_count_old_to_write = int(prev_sub_count or 0)
                    else:
                        subqueue_count_old_to_write = existing_subqueue_count_old
            else:
                # No explicit selected_subname determined: preserve existing value
                subqueue_count_old_to_write = existing_subqueue_count_old
        except Exception:
            subqueue_count_old_to_write = int(prev_sub_count or 0)

        # If no new selected_subname provided, preserve existing selected_subqueue
        new_selected = selected_subname if selected_subname else existing_selected
        # subqueue_count_new should reflect the new value for the selected subqueue if one was adjusted,
        # otherwise preserve existing subqueue_count_new
        new_subqueue_count_new = (
            sub_counts.get(selected_subname)
            if selected_subname
            else existing_subqueue_count_new
        )

        cur.execute(
            "UPDATE queues SET main_queue_count = %s, subqueue_counts = %s, selected_subqueue = %s, queue_count_old = %s, queue_count_new = %s, subqueue_count_old = %s, subqueue_count_new = %s, updated_at = NOW() WHERE id = %s",
            (
                main_count,
                json.dumps(sub_counts),
                new_selected,
                queue_count_old_to_write,
                main_count,
                subqueue_count_old_to_write,
                new_subqueue_count_new,
                queue_id,
            ),
        )
    except Exception as e:
        print(f"[_adjust_queue_counts] Failed to update queue counts: {e}")
        raise


@app.route("/cards", methods=["POST"])
def add_card():
    data = request.json or {}
    print("[CARDS] Incoming payload:", data)
    session_id = data.get("session_id")
    card_id = data.get("card_id")
    status = data.get("status")
    queue_id = data.get("queue_id")
    metadata = data.get("metadata")

    if not session_id or not card_id or not status or not queue_id:
        print("[CARDS] Missing required fields")
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
        print(f"[CARDS] Invalid status value: {status}")
        return jsonify({"success": False, "error": "Invalid status value"}), 400

    try:
        conn = get_conn()
        cur = conn.cursor()

        # ensure session exists
        cur.execute("SELECT id FROM sessions WHERE id = %s", (session_id,))
        if not cur.fetchone():
            print(f"[CARDS] Session not found for session_id={session_id}")
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Session not found"}), 404

        # ensure queue exists and belongs to session
        cur.execute(
            "SELECT id FROM queues WHERE id = %s AND session_id = %s",
            (queue_id, session_id),
        )
        if not cur.fetchone():
            print(
                f"[CARDS] Queue not found for queue_id={queue_id} session_id={session_id}"
            )
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
        print(f"[CARDS] Card inserted/updated: id={card_db_id}")
        # Fetch updated queue counts to return to caller
        try:
            cur.execute(
                "SELECT id, name, main_queue_count, subqueue_counts, selected_subqueue, queue_count_old, queue_count_new, subqueue_count_old, subqueue_count_new FROM queues WHERE id = %s",
                (queue_id,),
            )
            qrow = cur.fetchone()
            queue_info = None
            if qrow:
                queue_info = {
                    "id": qrow[0],
                    "name": qrow[1],
                    "main_queue_count": qrow[2],
                    "subqueue_counts": json.loads(qrow[3]) if qrow[3] else {},
                    "selected_subqueue": qrow[4],
                    "queue_count_old": qrow[5],
                    "queue_count_new": qrow[6],
                    "subqueue_count_old": qrow[7],
                    "subqueue_count_new": qrow[8],
                }
        except Exception as e:
            print(f"[CARDS] Failed to fetch queue info: {e}")
            queue_info = None

        cur.close()
        conn.close()
        return jsonify({"success": True, "card_id": card_db_id, "queue": queue_info})
    except Exception as e:
        print(f"[CARDS] Exception: {e}")
        import traceback

        traceback.print_exc()
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
