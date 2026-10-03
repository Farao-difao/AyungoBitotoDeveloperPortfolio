"""
app.py — Campus Delegate Voting Platform
========================================
Main Flask application.  Run with:
    python app.py          (debug mode)
    flask run              (uses FLASK_APP=app.py)
"""

import csv
import io
import os
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_bcrypt import Bcrypt
from flask_mysqldb import MySQL
from werkzeug.utils import secure_filename

# ── Bootstrap ────────────────────────────────────────────────────────────────
load_dotenv()   # Load .env file if present

app = Flask(__name__)
app.config.from_object("config.Config")

mysql = MySQL(app)
bcrypt = Bcrypt(app)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def get_cursor():
    """Return a DictCursor for the current MySQL connection."""
    return mysql.connection.cursor()


def get_settings():
    """Fetch the single voting_settings row (id=1). Cached on g per request."""
    if not hasattr(g, "settings"):
        cur = get_cursor()
        cur.execute("SELECT * FROM voting_settings WHERE id = 1")
        g.settings = cur.fetchone()
        cur.close()
    return g.settings


def voting_is_open():
    """
    Return True when voting is currently allowed.
    Rules:
      1. voting_open flag must be TRUE.
      2. If end_time is set, current time must be before it.
      3. If start_time is set, current time must be after it.
    """
    s = get_settings()
    if not s or not s["voting_open"]:
        return False
    now = datetime.now()
    if s["start_time"] and now < s["start_time"]:
        return False
    if s["end_time"] and now > s["end_time"]:
        return False
    return True


def allowed_file(filename):
    """Check upload extension."""
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in app.config["ALLOWED_EXTENSIONS"]
    )


# ── Context processor — inject settings into every template ─────────────────
@app.context_processor
def inject_now():
    """Inject current datetime so templates can use {{ now.year }}."""
    return dict(now=datetime.now())


@app.context_processor
def inject_settings():
    try:
        settings = get_settings()
    except Exception:
        settings = {
            "election_title": "Campus Delegate Election",
            "voting_open": False,
            "start_time": None,
            "end_time": None,
        }
    return dict(settings=settings)


# ═══════════════════════════════════════════════════════════════════════════════
# Auth decorators
# ═══════════════════════════════════════════════════════════════════════════════

def login_required(f):
    """Protect student-facing routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "student_db_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Protect admin routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin_id" not in session:
            flash("Admin login required.", "warning")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated


# ═══════════════════════════════════════════════════════════════════════════════
# Student Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    # Already logged in?
    if "student_db_id" in session:
        return redirect(url_for("vote"))

    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()
        password   = request.form.get("password", "")

        if not student_id or not password:
            flash("Please enter your Student ID and password.", "warning")
            return redirect(url_for("login"))

        cur = get_cursor()
        cur.execute(
            "SELECT * FROM students WHERE student_id = %s", (student_id,)
        )
        student = cur.fetchone()
        cur.close()

        if not student or not bcrypt.check_password_hash(
            student["password_hash"], password
        ):
            flash("Invalid Student ID or password.", "danger")
            return redirect(url_for("login"))

        # Successful authentication
        session["student_db_id"] = student["id"]
        session["student_name"]  = student["full_name"]
        session["student_id"]    = student["student_id"]

        if student["has_voted"]:
            flash("You have already voted. Here are the live results.", "info")
            return redirect(url_for("results"))

        if not voting_is_open():
            flash("Voting is currently closed.", "warning")
            return redirect(url_for("results"))

        return redirect(url_for("vote"))

    return render_template("login.html", settings=get_settings())


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/vote", methods=["GET"])
@login_required
def vote():
    # Redirect if already voted
    cur = get_cursor()
    cur.execute(
        "SELECT has_voted FROM students WHERE id = %s",
        (session["student_db_id"],),
    )
    row = cur.fetchone()
    if row and row["has_voted"]:
        flash("You have already cast your vote.", "info")
        cur.close()
        return redirect(url_for("results"))

    if not voting_is_open():
        flash("Voting is currently closed.", "warning")
        cur.close()
        return redirect(url_for("results"))

    cur.execute("SELECT * FROM candidates ORDER BY full_name")
    candidates = cur.fetchall()
    cur.close()
    return render_template("vote.html", candidates=candidates, settings=get_settings())


@app.route("/vote", methods=["POST"])
@login_required
def cast_vote():
    candidate_id = request.form.get("candidate_id")

    if not candidate_id:
        flash("Please select a candidate before submitting.", "warning")
        return redirect(url_for("vote"))

    student_db_id = session["student_db_id"]
    conn = mysql.connection
    cur  = conn.cursor()

    try:
        # ── Atomic check + insert ─────────────────────────────────────────
        # 1. Verify student hasn't voted (application-level check)
        cur.execute(
            "SELECT has_voted FROM students WHERE id = %s FOR UPDATE",
            (student_db_id,),
        )
        row = cur.fetchone()
        if not row:
            raise ValueError("Student record not found.")

        # DictCursor — value may be keyed differently depending on driver
        has_voted_val = list(row.values())[0] if isinstance(row, dict) else row[0]
        if has_voted_val:
            flash("You have already voted.", "warning")
            conn.rollback()
            return redirect(url_for("results"))

        if not voting_is_open():
            flash("Voting has closed.", "warning")
            conn.rollback()
            return redirect(url_for("results"))

        # 2. Verify candidate exists
        cur.execute(
            "SELECT id FROM candidates WHERE id = %s", (candidate_id,)
        )
        if not cur.fetchone():
            flash("Invalid candidate selected.", "danger")
            conn.rollback()
            return redirect(url_for("vote"))

        # 3. Insert vote (UNIQUE KEY prevents duplicates at DB level too)
        cur.execute(
            "INSERT INTO votes (student_db_id, candidate_id) VALUES (%s, %s)",
            (student_db_id, candidate_id),
        )

        # 4. Mark student as voted
        cur.execute(
            "UPDATE students SET has_voted = TRUE WHERE id = %s",
            (student_db_id,),
        )

        conn.commit()
        flash("Your vote has been recorded successfully!", "success")
        return redirect(url_for("voted"))

    except Exception as exc:
        conn.rollback()
        # Handle duplicate-key violation gracefully
        err_msg = str(exc).lower()
        if "duplicate" in err_msg or "1062" in err_msg:
            flash("You have already voted.", "warning")
            return redirect(url_for("results"))
        app.logger.error("Vote error: %s", exc)
        flash("An error occurred while recording your vote. Please try again.", "danger")
        return redirect(url_for("vote"))
    finally:
        cur.close()


@app.route("/voted")
@login_required
def voted():
    return render_template("voted.html")


@app.route("/results")
def results():
    """
    Live results page.  Accessible to:
      - Any logged-in student who has already voted.
      - Any logged-in student when voting is closed.
      - Admin sessions.
    """
    is_student = "student_db_id" in session
    is_admin   = "admin_id" in session

    if not is_student and not is_admin:
        flash("Please log in to view results.", "warning")
        return redirect(url_for("login"))

    # Students who haven't voted yet and voting is still open → back to vote
    if is_student and not is_admin:
        cur = get_cursor()
        cur.execute(
            "SELECT has_voted FROM students WHERE id = %s",
            (session["student_db_id"],),
        )
        row = cur.fetchone()
        cur.close()
        if row and not row["has_voted"] and voting_is_open():
            flash("Please cast your vote first.", "info")
            return redirect(url_for("vote"))

    cur = get_cursor()
    cur.execute(
        """
        SELECT c.id, c.full_name, c.position, c.photo_filename,
               COUNT(v.id) AS vote_count
        FROM   candidates c
        LEFT JOIN votes v ON v.candidate_id = c.id
        GROUP  BY c.id
        ORDER  BY vote_count DESC, c.full_name
        """
    )
    candidates = cur.fetchall()

    cur.execute("SELECT COUNT(*) AS total FROM votes")
    total_row   = cur.fetchone()
    total_votes = total_row["total"] if total_row else 0
    cur.close()

    # Attach percentage to each candidate
    for c in candidates:
        c["percentage"] = (
            round(c["vote_count"] / total_votes * 100, 1) if total_votes else 0
        )

    return render_template(
        "results.html",
        candidates=candidates,
        total_votes=total_votes,
        voting_open=voting_is_open(),
        settings=get_settings(),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Admin Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if "admin_id" in session:
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        cur = get_cursor()
        cur.execute("SELECT * FROM admins WHERE username = %s", (username,))
        admin = cur.fetchone()
        cur.close()

        if admin and bcrypt.check_password_hash(admin["password_hash"], password):
            session["admin_id"]       = admin["id"]
            session["admin_username"] = admin["username"]
            flash(f"Welcome back, {admin['username']}!", "success")
            return redirect(url_for("admin_dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("admin/login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_id", None)
    session.pop("admin_username", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    cur = get_cursor()
    cur.execute("SELECT COUNT(*) AS total FROM students")
    total_students = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM votes")
    total_votes = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM candidates")
    total_candidates = cur.fetchone()["total"]

    turnout = (
        round(total_votes / total_students * 100, 1) if total_students else 0
    )
    cur.close()

    return render_template(
        "admin/dashboard.html",
        total_students=total_students,
        total_votes=total_votes,
        total_candidates=total_candidates,
        turnout=turnout,
        settings=get_settings(),
    )


# ── Candidates ───────────────────────────────────────────────────────────────

@app.route("/admin/candidates")
@admin_required
def admin_candidates():
    cur = get_cursor()
    cur.execute(
        """
        SELECT c.*, COUNT(v.id) AS vote_count
        FROM   candidates c
        LEFT JOIN votes v ON v.candidate_id = c.id
        GROUP  BY c.id
        ORDER  BY c.created_at DESC
        """
    )
    candidates = cur.fetchall()
    cur.close()
    return render_template("admin/candidates.html", candidates=candidates)


@app.route("/admin/candidates/add", methods=["POST"])
@admin_required
def admin_add_candidate():
    full_name = request.form.get("full_name", "").strip()
    position  = request.form.get("position", "Delegate").strip()
    bio       = request.form.get("bio", "").strip()

    if not full_name:
        flash("Candidate name is required.", "warning")
        return redirect(url_for("admin_candidates"))

    photo_filename = None
    file = request.files.get("photo")
    if file and file.filename and allowed_file(file.filename):
        photo_filename = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], photo_filename))

    cur = get_cursor()
    cur.execute(
        "INSERT INTO candidates (full_name, position, bio, photo_filename) VALUES (%s,%s,%s,%s)",
        (full_name, position, bio or None, photo_filename),
    )
    mysql.connection.commit()
    cur.close()
    flash(f"Candidate '{full_name}' added successfully.", "success")
    return redirect(url_for("admin_candidates"))


@app.route("/admin/candidates/delete/<int:cid>", methods=["POST"])
@admin_required
def admin_delete_candidate(cid):
    cur = get_cursor()
    cur.execute("DELETE FROM candidates WHERE id = %s", (cid,))
    mysql.connection.commit()
    cur.close()
    flash("Candidate deleted.", "success")
    return redirect(url_for("admin_candidates"))


# ── Students ─────────────────────────────────────────────────────────────────

@app.route("/admin/students")
@admin_required
def admin_students():
    cur = get_cursor()
    cur.execute("SELECT * FROM students ORDER BY created_at DESC")
    students = cur.fetchall()
    cur.close()
    return render_template("admin/students.html", students=students)


@app.route("/admin/students/add", methods=["POST"])
@admin_required
def admin_add_student():
    student_id = request.form.get("student_id", "").strip()
    full_name  = request.form.get("full_name", "").strip()
    password   = request.form.get("password", "").strip()

    if not student_id or not full_name or not password:
        flash("All fields are required.", "warning")
        return redirect(url_for("admin_students"))

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        cur = get_cursor()
        cur.execute(
            "INSERT INTO students (student_id, full_name, password_hash) VALUES (%s,%s,%s)",
            (student_id, full_name, password_hash),
        )
        mysql.connection.commit()
        cur.close()
        flash(f"Student '{full_name}' ({student_id}) added successfully.", "success")
    except Exception as exc:
        if "duplicate" in str(exc).lower() or "1062" in str(exc):
            flash(f"Student ID '{student_id}' already exists.", "danger")
        else:
            flash("Error adding student.", "danger")
            app.logger.error("Add student error: %s", exc)

    return redirect(url_for("admin_students"))


@app.route("/admin/students/delete/<int:sid>", methods=["POST"])
@admin_required
def admin_delete_student(sid):
    cur = get_cursor()
    cur.execute("DELETE FROM students WHERE id = %s", (sid,))
    mysql.connection.commit()
    cur.close()
    flash("Student deleted.", "success")
    return redirect(url_for("admin_students"))


# ── Settings ─────────────────────────────────────────────────────────────────

@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        title        = request.form.get("election_title", "").strip()
        start_time   = request.form.get("start_time") or None
        end_time     = request.form.get("end_time") or None
        voting_open  = 1 if request.form.get("voting_open") == "1" else 0

        cur = get_cursor()
        cur.execute(
            """UPDATE voting_settings
               SET election_title = %s,
                   start_time     = %s,
                   end_time       = %s,
                   voting_open    = %s
               WHERE id = 1""",
            (title, start_time, end_time, voting_open),
        )
        mysql.connection.commit()
        cur.close()

        # Clear cached settings so next request re-fetches
        if hasattr(g, "settings"):
            del g.settings

        flash("Settings updated successfully.", "success")
        return redirect(url_for("admin_settings"))

    return render_template("admin/settings.html", settings=get_settings())


# ── Admin Results ─────────────────────────────────────────────────────────────

@app.route("/admin/results")
@admin_required
def admin_results():
    cur = get_cursor()
    cur.execute(
        """
        SELECT c.id, c.full_name, c.position,
               COUNT(v.id) AS vote_count
        FROM   candidates c
        LEFT JOIN votes v ON v.candidate_id = c.id
        GROUP  BY c.id
        ORDER  BY vote_count DESC
        """
    )
    candidates = cur.fetchall()

    cur.execute("SELECT COUNT(*) AS total FROM votes")
    total_votes = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM students")
    total_students = cur.fetchone()["total"]
    cur.close()

    for c in candidates:
        c["percentage"] = (
            round(c["vote_count"] / total_votes * 100, 1) if total_votes else 0
        )

    turnout = (
        round(total_votes / total_students * 100, 1) if total_students else 0
    )

    return render_template(
        "admin/results.html",
        candidates=candidates,
        total_votes=total_votes,
        total_students=total_students,
        turnout=turnout,
    )


# ── CSV Export ───────────────────────────────────────────────────────────────

@app.route("/admin/export/csv")
@admin_required
def admin_export_csv():
    cur = get_cursor()
    cur.execute(
        """
        SELECT s.student_id, s.full_name AS student_name,
               c.full_name AS candidate_name, c.position,
               v.voted_at
        FROM   votes v
        JOIN   students  s ON s.id = v.student_db_id
        JOIN   candidates c ON c.id = v.candidate_id
        ORDER  BY v.voted_at
        """
    )
    rows = cur.fetchall()
    cur.close()

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["student_id", "student_name", "candidate_name", "position", "voted_at"],
    )
    writer.writeheader()
    writer.writerows(rows)

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = (
        "attachment; filename=campus_vote_export.csv"
    )
    response.headers["Content-type"] = "text/csv"
    return response


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000,debug=True)
