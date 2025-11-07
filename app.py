from flask import Flask, request, jsonify
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone
from flask_cors import CORS
import re
import secrets

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


# Hardcoded database connection string for Vercel deployment
DATABASE_URL = "postgresql://postgres:luqman.ahmad1@db.nhmrfxrpwjeufaxgukes.supabase.co:5432/postgres"


def get_conn():
    """Create and return a database connection with autocommit enabled"""
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


# --- REGISTER (create new user with duplicate prevention) ---
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    # Validate input
    if not username or not password:
        return (
            jsonify({"success": False, "error": "Username and password are required"}),
            400,
        )

    # Validate username format
    is_valid, error_msg = validate_username(username)
    if not is_valid:
        return jsonify({"success": False, "error": error_msg}), 400

    # Validate password format
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return jsonify({"success": False, "error": error_msg}), 400

    # Check for duplicate username and insert
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Username already exists"}), 409

        cur.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id",
            (username, password),
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"success": True, "user_id": user_id})
    except Exception as e:
        return (
            jsonify(
                {"success": False, "error": "Failed to create user", "detail": str(e)}
            ),
            500,
        )


# --- LOGIN (create new session for the user) ---
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute(
            "SELECT id FROM users WHERE username = %s AND password = %s",
            (username, password),
        )
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return jsonify({"success": False}), 401

        user_id = row["id"]
        session_id = generate_session_id()
        starttime = datetime.now(timezone.utc)
        cur.execute(
            "INSERT INTO sessions (id, user_id, starttime) VALUES (%s, %s, %s)",
            (session_id, user_id, starttime),
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"success": True, "session_id": session_id})
    except Exception as e:
        return (
            jsonify({"success": False, "error": "Login failed", "detail": str(e)}),
            500,
        )


# --- LOGOUT (set endtime + duration on last session) ---
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
            "SELECT starttime, total_videos_watched FROM sessions WHERE id = %s",
            (session_id,),
        )
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Session not found"}), 404

        starttime = row[0]
        total_videos = row[1]
        endtime = datetime.now(timezone.utc)
        duration = None
        if starttime:
            duration = (endtime - starttime).total_seconds()

        cur.execute(
            "UPDATE sessions SET endtime = %s, duration = %s WHERE id = %s",
            (endtime, duration, session_id),
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
    loop_time = int(data.get("loopTime", 0))
    status = data.get("status", "Not Watched")

    try:
        conn = get_conn()
        cur = conn.cursor()

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
                    pass
            # --- RETROACTIVE KEY ASSIGNMENT ---
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
                        cur.execute(
                            "DELETE FROM video_keys WHERE video_id = %s AND key_value IS NULL",
                            (prev_vid,),
                        )
                        cur.execute(
                            "INSERT INTO video_keys (video_id, key_value) VALUES (%s, %s) ON CONFLICT (video_id, key_value) DO NOTHING",
                            (prev_vid, k),
                        )
            except Exception as e:
                print(f"[LOG_VIDEO] Retroactive key assignment failed: {e}")

        # Insert speeds (always insert at least one default speed)
        if not speeds or len(speeds) == 0:
            speeds = [1.0]

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
            except Exception:
                try:
                    cur.execute(
                        "INSERT INTO video_speeds (video_id, speed_value) VALUES (%s, %s) ON CONFLICT (video_id, speed_value) DO NOTHING",
                        (vid, 1.0),
                    )
                except Exception:
                    pass

        conn.commit()
        print(f"[LOG_VIDEO] COMMIT SUCCESSFUL for video_id={vid}")

        cur.close()
        conn.close()

        # VERIFICATION: Use NEW connection to check if video persists
        try:
            import time

            time.sleep(0.5)
            verify_conn = get_conn()
            verification_cur = verify_conn.cursor()
            verification_cur.execute(
                "SELECT watched, loop_time FROM videos WHERE id = %s", (vid,)
            )
            verify_result = verification_cur.fetchone()
            if verify_result:
                print(
                    f"[LOG_VIDEO] VERIFIED: Video {vid} exists in DB with watched={verify_result[0]}, loop_time={verify_result[1]}"
                )
            else:
                print(f"[LOG_VIDEO] ERROR: Video {vid} NOT FOUND after commit!")
            verification_cur.close()
            verify_conn.close()
        except Exception as ve:
            print(f"[LOG_VIDEO] Verification failed: {ve}")

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
        print(f"[LOG_VIDEO] FUNCTION COMPLETING SUCCESSFULLY for video_id={vid}")
        return jsonify({"success": True, "video": video_entry})
    except Exception as e:
        print(f"[LOG_VIDEO] EXCEPTION OCCURRED: {str(e)}")
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


if __name__ == "__main__":
    import os

    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
