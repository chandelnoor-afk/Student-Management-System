from flask import (Flask, json, request, render_template, redirect, url_for,
                   jsonify, session)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import functools
import os
import secrets
import sqlite3
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Session configuration
# ---------------------------------------------------------------------------
def load_secret_key():
    """Key used to sign the session cookie. Taken from the environment if set,
    otherwise created once and kept in secret_key.txt next to this file."""
    key = os.environ.get("SMS_SECRET_KEY")
    if key:
        return key
    path = os.path.join(BASE_DIR, "secret_key.txt")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app.secret_key = load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,     # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",    # cookie is not sent with cross-site POSTs
)

MIN_PASSWORD_LENGTH = 8
MAX_FAILED_LOGINS = 5
LOCK_SECONDS = 300
failed_logins = {}   # e-mail -> (number of failures, time of last failure)
# Checked when the e-mail is unknown, so that a wrong e-mail takes as long as a wrong password
DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


# Email-based role detection
def get_role_from_email(email):
    """Determine user role based on email domain"""
    if email.endswith("@teacher.com"):
        return "teacher"
    elif email.endswith("@student.com"):
        return "student"
    elif email.endswith("@admin.com"):
        return "admin"
    return None


# Database Connection
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# Initialize database
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Login accounts. Passwords are stored only as salted hashes.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exam_answers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_email TEXT,
            subject TEXT,
            answers TEXT
        )
    """)

    # Table for storing teacher availability
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS teacher_availability (
            teacher_name TEXT PRIMARY KEY,
            is_available INTEGER
        )
    """)

    # Table for storing subject results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_email TEXT NOT NULL,
            subject TEXT NOT NULL,
            marks INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table for storing quiz results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS quiz_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_email TEXT NOT NULL,
            subject TEXT NOT NULL,
            score INTEGER NOT NULL,
            total_questions INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table for storing student details
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            email TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            roll TEXT NOT NULL,
            course TEXT NOT NULL,
            division TEXT NOT NULL,
            fees TEXT NOT NULL
        )
    """)

    # Table for storing teacher details
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS teachers (
            email TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            phone TEXT,
            department TEXT,
            subject TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table for storing exams
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exams (
            subject TEXT PRIMARY KEY,
            is_active INTEGER,
            questions TEXT
        )
    """)

    # Table for storing quizzes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS quizzes (
            subject TEXT PRIMARY KEY,
            is_active INTEGER,
            questions TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_email TEXT,
            date TEXT,
            status TEXT,
            teacher_email TEXT,
            subject TEXT,
            UNIQUE(student_email, date, teacher_email, subject)
        )
    """)

    # Add teacher_email column if it doesn't exist
    try:
        cursor.execute("ALTER TABLE attendance ADD COLUMN teacher_email TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Add subject column if it doesn't exist
    try:
        cursor.execute("ALTER TABLE attendance ADD COLUMN subject TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # The old student_locations table was never used. It is removed so that
    # no location data is kept.
    cursor.execute("DROP TABLE IF EXISTS student_locations")

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Login, sessions and role checks
# ---------------------------------------------------------------------------
def admin_exists():
    conn = get_db_connection()
    row = conn.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").fetchone()
    conn.close()
    return row is not None


def set_password(cursor, email, password):
    """Create the login account of `email` or replace its password."""
    cursor.execute("""
        INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash
    """, (email, generate_password_hash(password), get_role_from_email(email)))


def deny(status, page):
    """Answer for a request that is not allowed."""
    if page:
        if status == 401:
            return redirect(url_for("home"))
        return "Access denied", 403
    message = "Login required" if status == 401 else "Access denied"
    return jsonify({"success": False, "error": message}), status


def login_required(*roles, page=False):
    """Allow the route only for a logged-in user with one of the given roles.
    page=True is used for routes that return an HTML page."""
    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            if "email" not in session:
                return deny(401, page)
            if roles and session.get("role") not in roles:
                return deny(403, page)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def is_own(email):
    """True when the e-mail in the URL belongs to the logged-in user."""
    return session.get("email") == email


def dashboard_url():
    return f"/{session['role']}/{session['email']}"


# Fetch latest results per subject for students
def get_latest_results(email):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT subject, marks
        FROM results
        WHERE student_email = ?
        AND id IN (
            SELECT MAX(id)
            FROM results
            WHERE student_email = ?
            GROUP BY subject
        )
    """, (email, email))

    results = cursor.fetchall()
    conn.close()
    return results


# Fetch latest quiz results for students
def get_latest_quiz_results(email):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT subject, score, total_questions
        FROM quiz_results
        WHERE student_email = ?
        AND id IN (
            SELECT MAX(id)
            FROM quiz_results
            WHERE student_email = ?
            GROUP BY subject
        )
    """, (email, email))

    quiz_results = cursor.fetchall()
    conn.close()
    return quiz_results


@app.route("/")
def home():
    if not admin_exists():
        return redirect(url_for("setup"))
    if "email" in session:
        return redirect(dashboard_url())
    return render_template("index.html")


@app.route("/setup", methods=["GET", "POST"])
def setup():
    """First run only: create the administrator account."""
    if admin_exists():
        return redirect(url_for("home"))
    error = None
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        if get_role_from_email(email) != "admin":
            error = "The administrator e-mail must end with @admin.com"
        elif len(password) < MIN_PASSWORD_LENGTH:
            error = f"The password needs at least {MIN_PASSWORD_LENGTH} characters"
        elif password != confirm:
            error = "The two passwords are not the same"
        else:
            conn = get_db_connection()
            set_password(conn.cursor(), email, password)
            conn.commit()
            conn.close()
            return redirect(url_for("home"))
    return render_template("setup.html", error=error)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or "@" not in email:
        return jsonify({"success": False, "error": "Invalid email format"})

    role = get_role_from_email(email)
    if role is None:
        return jsonify({"success": False, "error": "Invalid email domain. Use @teacher.com, @student.com or @admin.com"})

    # Stop repeated guessing of one account
    count, last = failed_logins.get(email, (0, 0))
    if count >= MAX_FAILED_LOGINS and time.time() - last < LOCK_SECONDS:
        return jsonify({"success": False, "error": "Too many wrong attempts. Try again after 5 minutes."}), 429

    conn = get_db_connection()
    user = conn.execute("SELECT password_hash, role FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    stored_hash = user["password_hash"] if user else DUMMY_HASH
    password_ok = check_password_hash(stored_hash, password)
    if user is None or not password_ok:
        if count >= MAX_FAILED_LOGINS:
            count = 0   # the lock time is over, start counting again
        failed_logins[email] = (count + 1, time.time())
        return jsonify({"success": False, "error": "Wrong e-mail or password"})

    failed_logins.pop(email, None)
    session.clear()
    session["email"] = email
    session["role"] = user["role"]
    return jsonify({"success": True, "redirect": dashboard_url()})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/account")
@login_required(page=True)
def account():
    return render_template("account.html", email=session["email"], back=dashboard_url())


@app.route("/change_password", methods=["POST"])
@login_required()
def change_password():
    data = request.get_json(silent=True) or {}
    old = data.get("old_password") or ""
    new = data.get("new_password") or ""

    if len(new) < MIN_PASSWORD_LENGTH:
        return jsonify({"success": False, "error": f"The new password needs at least {MIN_PASSWORD_LENGTH} characters"})

    conn = get_db_connection()
    cursor = conn.cursor()
    user = cursor.execute("SELECT password_hash FROM users WHERE email = ?", (session["email"],)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], old):
        conn.close()
        return jsonify({"success": False, "error": "The current password is wrong"})

    set_password(cursor, session["email"], new)
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
@app.route("/admin/<email>")
@login_required("admin", page=True)
def admin(email):
    if not is_own(email):
        return deny(403, True)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    teachers = cur.execute("SELECT email, name, department, subject FROM teachers").fetchall()
    quiz = cur.execute("SELECT id, student_email, subject, score FROM quiz_results").fetchall()
    exams = cur.execute("SELECT id, student_email, subject, marks FROM results").fetchall()
    students = cur.execute("""
        SELECT email, name, roll, course, division, fees
        FROM students
        ORDER BY CAST(roll AS INTEGER)
    """).fetchall()
    accounts = {row[0] for row in cur.execute("SELECT email FROM users")}
    conn.close()

    no_password = [s[0] for s in students if s[0] not in accounts] + \
                  [t[0] for t in teachers if t[0] not in accounts]

    return render_template("admin.html",
                           students=students,
                           teachers=teachers,
                           quiz=quiz,
                           exams=exams,
                           no_password=no_password,
                           message=request.args.get("message"))


@app.route('/admin_add_student', methods=['POST'])
@login_required("admin", page=True)
def admin_add_student():
    name = request.form.get('name')
    email = (request.form.get('email') or "").strip().lower()
    roll = request.form.get('roll')
    course = request.form.get('course')
    division = request.form.get('division')
    fees = request.form.get('fees')
    password = request.form.get('password') or ""

    if get_role_from_email(email) != "student":
        return redirect(dashboard_url() + "?message=Student e-mail must end with @student.com")
    if password and len(password) < MIN_PASSWORD_LENGTH:
        return redirect(dashboard_url() + f"?message=Password needs at least {MIN_PASSWORD_LENGTH} characters")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO students (email, name, roll, course, division, fees)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
        name=excluded.name,
        roll=excluded.roll,
        course=excluded.course,
        division=excluded.division,
        fees=excluded.fees
    """, (email, name, roll, course, division, fees))
    if password:
        set_password(cursor, email, password)

    conn.commit()
    conn.close()

    return redirect(dashboard_url() + "?message=Student saved")


@app.route("/delete_student/<email>", methods=["POST"])
@login_required("admin")
def delete_student(email):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM students WHERE email = ?", (email,))
    cursor.execute("DELETE FROM attendance WHERE student_email = ?", (email,))
    cursor.execute("DELETE FROM quiz_results WHERE student_email = ?", (email,))
    cursor.execute("DELETE FROM results WHERE student_email = ?", (email,))
    cursor.execute("DELETE FROM exam_answers WHERE student_email = ?", (email,))
    cursor.execute("DELETE FROM users WHERE email = ? AND role = 'student'", (email,))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/delete_teacher/<email>", methods=["POST"])
@login_required("admin")
def delete_teacher(email):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM teachers WHERE email = ?", (email,))
    cursor.execute("DELETE FROM teacher_availability WHERE teacher_name = ?", (email,))
    cursor.execute("DELETE FROM users WHERE email = ? AND role = 'teacher'", (email,))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route('/admin_add_teacher', methods=['POST'])
@login_required("admin", page=True)
def admin_add_teacher():
    name = request.form.get('name')
    email = (request.form.get('email') or "").strip().lower()
    department = request.form.get('department')
    subject = request.form.get('subject')
    password = request.form.get('password') or ""

    if get_role_from_email(email) != "teacher":
        return redirect(dashboard_url() + "?message=Teacher e-mail must end with @teacher.com")
    if password and len(password) < MIN_PASSWORD_LENGTH:
        return redirect(dashboard_url() + f"?message=Password needs at least {MIN_PASSWORD_LENGTH} characters")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO teachers (email, name, department, subject)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
        name=excluded.name,
        department=excluded.department,
        subject=excluded.subject
    """, (email, name, department, subject))
    if password:
        set_password(cursor, email, password)

    conn.commit()
    conn.close()

    return redirect(dashboard_url() + "?message=Teacher saved")


@app.route('/admin_set_password', methods=['POST'])
@login_required("admin", page=True)
def admin_set_password():
    """Give a registered student or teacher a password, or replace a forgotten one."""
    email = (request.form.get('email') or "").strip().lower()
    password = request.form.get('password') or ""
    role = get_role_from_email(email)

    if len(password) < MIN_PASSWORD_LENGTH:
        return redirect(dashboard_url() + f"?message=Password needs at least {MIN_PASSWORD_LENGTH} characters")

    conn = get_db_connection()
    cursor = conn.cursor()
    if role == "student":
        known = cursor.execute("SELECT 1 FROM students WHERE email = ?", (email,)).fetchone()
    elif role == "teacher":
        known = cursor.execute("SELECT 1 FROM teachers WHERE email = ?", (email,)).fetchone()
    else:
        known = None
    if not known:
        conn.close()
        return redirect(dashboard_url() + "?message=No student or teacher is registered with that e-mail")

    set_password(cursor, email, password)
    conn.commit()
    conn.close()
    failed_logins.pop(email, None)
    return redirect(dashboard_url() + "?message=Password saved")


@app.route("/delete_quiz/<int:id>", methods=["POST"])
@login_required("admin")
def delete_quiz(id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM quiz_results WHERE id = ?", (id,))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/delete_exam/<int:id>", methods=["POST"])
@login_required("admin")
def delete_exam(id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM results WHERE id = ?", (id,))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# Teacher
# ---------------------------------------------------------------------------
@app.route("/teacher/<teacher_email>")
@login_required("teacher", page=True)
def teacher_dashboard(teacher_email):
    if not is_own(teacher_email):
        return deny(403, True)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM results")
    results = cursor.fetchall()

    cursor.execute("SELECT student_email, subject, score, total_questions FROM quiz_results")
    quiz_results = cursor.fetchall()

    cursor.execute("SELECT * FROM students ORDER BY CAST(roll AS INTEGER) ASC")
    student_details = cursor.fetchall()

    # GET availability for this teacher
    cursor.execute("SELECT is_available FROM teacher_availability WHERE teacher_name = ?", (teacher_email,))
    availability = cursor.fetchone()

    # Get teacher details
    cursor.execute("SELECT name, phone, department, subject FROM teachers WHERE email = ?", (teacher_email,))
    teacher = cursor.fetchone()

    conn.close()

    return render_template(
        "teacher.html",
        results=results,
        quiz_results=quiz_results,
        student_details=student_details,
        students=student_details,
        availability=availability,
        teacher_email=teacher_email,
        teacher=teacher
    )


@app.route('/update_availability', methods=['POST'])
@login_required("teacher")
def update_availability():
    data = request.get_json(silent=True) or {}
    status = 1 if data.get("status") else 0

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO teacher_availability (teacher_name, is_available)
        VALUES (?, ?)
        ON CONFLICT(teacher_name) DO UPDATE SET
        is_available = excluded.is_available
    """, (session["email"], status))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/get_teacher_details/<teacher_email>")
@login_required("teacher", "admin")
def get_teacher_details(teacher_email):
    if session["role"] == "teacher" and not is_own(teacher_email):
        return deny(403, False)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name, phone, department, subject FROM teachers WHERE email = ?", (teacher_email,))
    teacher = cursor.fetchone()
    conn.close()

    if teacher:
        return jsonify({
            "success": True,
            "name": teacher[0],
            "phone": teacher[1],
            "department": teacher[2],
            "subject": teacher[3]
        })
    return jsonify({"success": False})


@app.route("/save_teacher_details", methods=["POST"])
@login_required("teacher")
def save_teacher_details():
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    phone = data.get("phone")
    department = data.get("department")
    subject = data.get("subject")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO teachers (email, name, phone, department, subject)
        VALUES (?, ?, ?, ?, ?)
    """, (session["email"], name, phone, department, subject))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/add_result", methods=["POST"])
@login_required("teacher", page=True)
def add_result():
    student_email = (request.form.get("student_email") or "").strip().lower()
    subject = (request.form.get("subject") or "").strip()
    marks = request.form.get("marks") or ""

    try:
        marks = int(marks)
    except ValueError:
        return "Marks must be a whole number", 400
    if not student_email or not subject or not 0 <= marks <= 100:
        return "Student e-mail, subject and marks between 0 and 100 are required", 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO results (student_email, subject, marks) VALUES (?, ?, ?)",
                   (student_email, subject, marks))
    conn.commit()
    conn.close()

    return redirect(url_for("teacher_dashboard", teacher_email=session["email"]))


@app.route('/add_student_details', methods=['POST'])
@login_required("teacher", page=True)
def add_student_details():
    student_email = (request.form.get('student_email') or "").strip().lower()
    student_name = request.form.get('student_name')
    student_roll = request.form.get('student_roll')
    student_course = request.form.get('student_course')
    student_division = request.form.get('student_div')
    student_fees = request.form.get('student_fees')

    if not student_email or not student_name or not student_roll or not student_course or not student_division or not student_fees:
        return jsonify({"error": "Missing required student details"}), 400
    if get_role_from_email(student_email) != "student":
        return jsonify({"error": "Student e-mail must end with @student.com"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Insert or update student details into the database.
    # The admin gives the student a password from the admin dashboard.
    cursor.execute("""
        INSERT INTO students (email, name, roll, course, division, fees)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
            name = excluded.name,
            roll = excluded.roll,
            course = excluded.course,
            division = excluded.division,
            fees = excluded.fees
    """, (student_email, student_name, student_roll, student_course, student_division, student_fees))

    conn.commit()
    conn.close()

    return redirect(url_for("teacher_dashboard", teacher_email=session["email"]))


@app.route('/getStudentDetails')
@login_required()
def get_student_details():
    student_email = request.args.get('email')

    if not student_email:
        return jsonify({"error": "Student email required"}), 400
    if session["role"] == "student" and not is_own(student_email):
        return deny(403, False)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM students WHERE email = ?", (student_email,))
    student = cursor.fetchone()

    conn.close()

    if student:
        return jsonify({
            "email": student["email"],
            "name": student["name"],
            "roll": student["roll"],
            "course": student["course"],
            "division": student["division"],
            "fees": student["fees"]
        })
    else:
        return jsonify({"error": "Student not found"}), 404


# ---------------------------------------------------------------------------
# Student
# ---------------------------------------------------------------------------
@app.route("/student/<email>")
@login_required("student", page=True)
def student_dashboard(email):
    if not is_own(email):
        return deny(403, True)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Student details
    cursor.execute("SELECT * FROM students WHERE email = ?", (email,))
    student = cursor.fetchone()

    # Fetch teacher availability
    cursor.execute("SELECT teacher_name, is_available FROM teacher_availability")
    teachers = cursor.fetchall()

    conn.close()

    if not student:
        return "Student details not found", 404

    results = get_latest_results(email)
    quiz_results = get_latest_quiz_results(email)

    return render_template(
        "student.html",
        email=email,
        student=student,
        results=results,
        quiz_results=quiz_results,
        teachers=teachers
    )


# ---------------------------------------------------------------------------
# Written test (IAT exam)
# ---------------------------------------------------------------------------
@app.route("/start_exam", methods=["POST"])
@login_required("teacher")
def start_exam():
    data = request.get_json(silent=True) or {}
    subject = data.get("subject")
    questions = data.get("questions")  # list of 10 questions

    if not subject or not questions:
        return jsonify({"success": False})

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO exams (subject, is_active, questions)
        VALUES (?, ?, ?)
        ON CONFLICT(subject) DO UPDATE SET
            is_active = 1,
            questions = excluded.questions
    """, (subject, 1, json.dumps(questions)))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/stop_exam/<subject>", methods=["POST"])
@login_required("teacher")
def stop_exam(subject):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE exams SET is_active = 0 WHERE subject = ?", (subject,))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/check_exam/<subject>")
@login_required("student", "teacher")
def check_exam(subject):
    is_student = session["role"] == "student"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT is_active, questions FROM exams WHERE subject=?", (subject,))
    row = cursor.fetchone()

    # Check if this student already submitted
    submitted = False
    if is_student:
        cursor.execute("SELECT id FROM exam_answers WHERE student_email=? AND subject=?",
                       (session["email"], subject))
        if cursor.fetchone():
            submitted = True

    conn.close()

    if row:
        active = row["is_active"] == 1
        # A student gets the questions only while the exam is running
        show = active or not is_student
        return jsonify({
            "active": active,
            "questions": json.loads(row["questions"]) if show else [],
            "submitted": submitted
        })

    return jsonify({"active": False, "submitted": submitted})


@app.route("/submit_exam", methods=["POST"])
@login_required("student")
def submit_exam():
    data = request.get_json(silent=True) or {}

    student = session["email"]          # taken from the session, not from the request
    subject = data.get("subject")
    answers = data.get("answers")

    if not subject or not answers:
        return jsonify({"success": False, "error": "Missing data"})

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("BEGIN IMMEDIATE")   # one submission at a time

    exam = cursor.execute("SELECT is_active FROM exams WHERE subject=?", (subject,)).fetchone()
    if not exam or exam["is_active"] != 1:
        conn.rollback()
        conn.close()
        return jsonify({"success": False, "error": "Exam is not active"})

    # Check if already submitted
    cursor.execute("SELECT id FROM exam_answers WHERE student_email=? AND subject=?",
                   (student, subject))
    if cursor.fetchone():
        conn.rollback()
        conn.close()
        return jsonify({"success": False, "error": "Exam already submitted"})

    cursor.execute("""
        INSERT INTO exam_answers (student_email, subject, answers)
        VALUES (?, ?, ?)
    """, (student, subject, json.dumps(answers)))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# Quiz
# ---------------------------------------------------------------------------
def correct_option(question):
    """Letter of the correct option of a stored quiz question."""
    if not isinstance(question, dict):
        return None
    value = question.get("correct") or question.get("answer") or question.get("correctAnswer")
    return str(value).strip().upper() if value else None


@app.route("/start_quiz", methods=["POST"])
@login_required("teacher")
def start_quiz():
    data = request.get_json(silent=True) or {}
    subject = data.get("subject")
    questions = data.get("questions")

    if not subject or not questions:
        return jsonify({"success": False, "error": "Missing subject or questions"})

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT subject FROM quizzes WHERE subject = ?", (subject,))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE quizzes
            SET is_active = 1, questions = ?
            WHERE subject = ?
        """, (json.dumps(questions), subject))
    else:
        cursor.execute("""
            INSERT INTO quizzes (subject, is_active, questions)
            VALUES (?, ?, ?)
        """, (subject, 1, json.dumps(questions)))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/stop_quiz/<subject>", methods=["POST"])
@login_required("teacher")
def stop_quiz(subject):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE quizzes SET is_active = 0 WHERE subject = ?", (subject,))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/check_quiz/<subject>")
@login_required("student", "teacher")
def check_quiz(subject):
    is_student = session["role"] == "student"

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check quiz status
    cursor.execute("SELECT is_active, questions FROM quizzes WHERE subject=?", (subject,))
    row = cursor.fetchone()

    # Check if this student already submitted
    submitted = False
    if is_student:
        cursor.execute("SELECT id FROM quiz_results WHERE student_email=? AND subject=?",
                       (session["email"], subject))
        if cursor.fetchone():
            submitted = True

    conn.close()

    if row:
        active = row["is_active"] == 1
        questions = json.loads(row["questions"])
        if is_student:
            # The correct options stay on the server. The student gets the
            # question text and the options only, and only while the quiz runs.
            questions = [
                {"question": q.get("question"), "options": q.get("options", [])}
                for q in questions if isinstance(q, dict)
            ] if active and not submitted else []
        return jsonify({
            "active": active,
            "questions": questions,
            "submitted": submitted
        })

    return jsonify({"active": False, "submitted": submitted})


@app.route("/submit_quiz", methods=["POST"])
@login_required("student")
def submit_quiz():
    """The student sends the chosen options. The score is worked out here."""
    data = request.get_json(silent=True) or {}

    student_email = session["email"]    # taken from the session, not from the request
    subject = data.get("subject")
    answers = data.get("answers")

    if not subject or not isinstance(answers, list):
        return jsonify({"success": False, "error": "Missing data"})

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("BEGIN IMMEDIATE")   # one submission at a time

    quiz = cursor.execute("SELECT is_active, questions FROM quizzes WHERE subject=?", (subject,)).fetchone()
    if not quiz or quiz["is_active"] != 1:
        conn.rollback()
        conn.close()
        return jsonify({"success": False, "error": "Quiz is not active"})

    # Only one attempt for each student and subject
    cursor.execute("SELECT id FROM quiz_results WHERE student_email=? AND subject=?",
                   (student_email, subject))
    if cursor.fetchone():
        conn.rollback()
        conn.close()
        return jsonify({"success": False, "error": "Quiz already submitted"})

    questions = json.loads(quiz["questions"])
    total_questions = len(questions)
    correct = 0
    for index, question in enumerate(questions):
        chosen = answers[index] if index < len(answers) else None
        if chosen and str(chosen).strip().upper() == correct_option(question):
            correct += 1
    score = round(100 * correct / total_questions) if total_questions else 0

    cursor.execute("INSERT INTO quiz_results (student_email, subject, score, total_questions) VALUES (?, ?, ?, ?)",
                   (student_email, subject, score, total_questions))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "score": score, "total_questions": total_questions})


# ---------------------------------------------------------------------------
# Attendance
# ---------------------------------------------------------------------------
@app.route('/save_attendance', methods=['POST'])
@login_required("teacher")
def save_attendance():
    data = request.get_json(silent=True) or {}
    date = data.get("date")
    attendance_data = data.get("attendance")
    teacher_email = session["email"]    # taken from the session, not from the request
    subject = data.get("subject", "")

    # Validation
    if not date or not attendance_data or not isinstance(attendance_data, dict):
        return jsonify({"success": False, "error": "Missing required fields"}), 400
    if any(status not in ("Present", "Absent") for status in attendance_data.values()):
        return jsonify({"success": False, "error": "Status must be Present or Absent"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        for student_email, status in attendance_data.items():
            cursor.execute("""
                INSERT INTO attendance (student_email, date, status, teacher_email, subject)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(student_email, date, teacher_email, subject) DO UPDATE SET
                status = excluded.status
            """, (student_email, date, status, teacher_email, subject))

        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        conn.close()


@app.route('/get_attendance')
@login_required("teacher")
def get_attendance():
    date = request.args.get("date")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT student_email, status FROM attendance WHERE date = ?", (date,))
    data = cursor.fetchall()

    conn.close()

    return jsonify({row["student_email"]: row["status"] for row in data})


@app.route('/get_student_attendance/<student_email>')
@login_required()
def get_student_attendance(student_email):
    if session["role"] == "student" and not is_own(student_email):
        return deny(403, False)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT date, status, teacher_email, subject FROM attendance
        WHERE student_email = ?
        ORDER BY date DESC
    """, (student_email,))

    records = cursor.fetchall()
    conn.close()

    return jsonify({
        "success": True,
        "records": [
            {
                "date": record["date"],
                "status": record["status"],
                "teacher_email": record["teacher_email"],
                "subject": record["subject"] if record["subject"] else "General"
            }
            for record in records
        ]
    })


# ---------------------------------------------------------------------------
# Analysis pages
# ---------------------------------------------------------------------------
@app.route("/quiz_analysis/<teacher_email>")
@login_required("teacher", page=True)
def quiz_analysis(teacher_email):
    if not is_own(teacher_email):
        return deny(403, True)
    subject = request.args.get("subject")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get all subjects if not specified
    if not subject:
        cursor.execute("SELECT DISTINCT subject FROM quiz_results ORDER BY subject")
        subjects = [row[0] for row in cursor.fetchall()]
        conn.close()
        return render_template("quiz_analysis.html",
                               teacher_email=teacher_email,
                               subjects=subjects,
                               quiz_data=None,
                               statistics=None,
                               selected_subject=None,
                               now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Get quiz results for specific subject
    cursor.execute("""
        SELECT qr.student_email, s.roll, s.name, qr.score, qr.total_questions, qr.timestamp
        FROM quiz_results qr
        JOIN students s ON qr.student_email = s.email
        WHERE qr.subject = ?
        ORDER BY CAST(s.roll AS INTEGER) ASC
    """, (subject,))

    quiz_results = cursor.fetchall()

    # Calculate statistics
    if quiz_results:
        scores = [float(row[3]) for row in quiz_results]
        average_score = sum(scores) / len(scores)
        highest_score = max(scores)
        lowest_score = min(scores)

        # Find topper and weak students
        topper = max(quiz_results, key=lambda x: float(x[3]))
        weak_students = [row for row in quiz_results if float(row[3]) < (average_score * 0.5)]

        statistics = {
            "subject": subject,
            "total_students": len(quiz_results),
            "average_score": round(average_score, 2),
            "highest_score": highest_score,
            "lowest_score": lowest_score,
            "topper_email": topper[0],
            "topper_name": topper[2],
            "topper_score": topper[3],
            "weak_students_count": len(weak_students)
        }
    else:
        statistics = None

    # Get all subjects
    cursor.execute("SELECT DISTINCT subject FROM quiz_results ORDER BY subject")
    subjects = [row[0] for row in cursor.fetchall()]
    conn.close()

    return render_template("quiz_analysis.html",
                           teacher_email=teacher_email,
                           quiz_data=quiz_results,
                           subjects=subjects,
                           statistics=statistics,
                           selected_subject=subject,
                           now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


@app.route("/attendance_analysis/<teacher_email>")
@login_required("teacher", page=True)
def attendance_analysis(teacher_email):
    if not is_own(teacher_email):
        return deny(403, True)
    subject = request.args.get("subject")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get all subjects if not specified
    if not subject:
        cursor.execute("SELECT DISTINCT subject FROM teachers WHERE email = ?", (teacher_email,))
        teacher = cursor.fetchone()
        if teacher:
            subject_list = [teacher[0]] if teacher[0] else []
        else:
            subject_list = []

        cursor.execute("SELECT DISTINCT subject FROM results ORDER BY subject")
        if not subject_list:
            subject_list = [row[0] for row in cursor.fetchall()]

        conn.close()
        return render_template("attendance_analysis.html",
                               teacher_email=teacher_email,
                               subjects=subject_list,
                               attendance_data=None,
                               now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Get unique students with their attendance summary
    cursor.execute("""
        SELECT DISTINCT s.email, s.roll, s.name
        FROM students s
        LEFT JOIN attendance a ON s.email = a.student_email
        ORDER BY CAST(s.roll AS INTEGER) ASC
    """)

    students_data = cursor.fetchall()

    # Calculate attendance statistics for each student
    attendance_summary = []
    for student in students_data:
        student_email, roll_no, name = student
        cursor.execute("""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN status = 'Present' THEN 1 ELSE 0 END) as present
            FROM attendance
            WHERE student_email = ?
        """, (student_email,))

        stats = cursor.fetchone()
        total_days = stats[0] if stats[0] else 0
        present_days = stats[1] if stats[1] else 0
        attendance_percentage = (present_days / total_days * 100) if total_days > 0 else 0

        attendance_summary.append({
            "email": student_email,
            "roll": roll_no,
            "name": name,
            "total_days": total_days,
            "present_days": present_days,
            "absent_days": total_days - present_days,
            "percentage": round(attendance_percentage, 2)
        })

    # Get all subjects
    cursor.execute("SELECT DISTINCT subject FROM results ORDER BY subject")
    subjects = [row[0] for row in cursor.fetchall()]
    conn.close()

    return render_template("attendance_analysis.html",
                           teacher_email=teacher_email,
                           attendance_data=attendance_summary,
                           subjects=subjects,
                           selected_subject=subject,
                           now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


@app.route("/iat_analysis/<teacher_email>")
@login_required("teacher", page=True)
def iat_analysis(teacher_email):
    if not is_own(teacher_email):
        return deny(403, True)
    subject = request.args.get("subject")

    conn = get_db_connection()
    cursor = conn.cursor()

    # If subject not selected, show subject list first
    if not subject:
        cursor.execute("SELECT DISTINCT subject FROM results ORDER BY subject")
        subjects = [row[0] for row in cursor.fetchall()]
        conn.close()

        return render_template(
            "iat_analysis.html",
            teacher_email=teacher_email,
            subjects=subjects,
            iat_data=None,
            statistics=None,
            selected_subject=None,
            now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

    # Get IAT marks for selected subject
    cursor.execute("""
        SELECT r.student_email, s.roll, s.name, r.marks
        FROM results r
        JOIN students s ON r.student_email = s.email
        WHERE r.subject = ?
        ORDER BY CAST(s.roll AS INTEGER) ASC
    """, (subject,))

    iat_results = cursor.fetchall()

    # Calculate statistics
    if iat_results:
        marks_list = [float(row[3]) for row in iat_results]

        average_marks = sum(marks_list) / len(marks_list)
        highest_marks = max(marks_list)
        lowest_marks = min(marks_list)

        topper = max(iat_results, key=lambda x: float(x[3]))
        weak_students = [row for row in iat_results if float(row[3]) < (average_marks * 0.5)]

        statistics = {
            "subject": subject,
            "total_students": len(iat_results),
            "average_marks": round(average_marks, 2),
            "highest_marks": highest_marks,
            "lowest_marks": lowest_marks,
            "topper_email": topper[0],
            "topper_roll": topper[1],
            "topper_name": topper[2],
            "topper_marks": topper[3],
            "weak_students_count": len(weak_students)
        }
    else:
        statistics = None

    # Load subject list again
    cursor.execute("SELECT DISTINCT subject FROM results ORDER BY subject")
    subjects = [row[0] for row in cursor.fetchall()]

    conn.close()

    return render_template(
        "iat_analysis.html",
        teacher_email=teacher_email,
        iat_data=iat_results,
        subjects=subjects,
        statistics=statistics,
        selected_subject=subject,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


init_db()

if __name__ == "__main__":
    # debug must stay off when other people can reach the server
    app.run(debug=os.environ.get("SMS_DEBUG") == "1")
