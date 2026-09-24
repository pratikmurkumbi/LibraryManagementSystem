from flask import jsonify
from flask import Flask, render_template, request, redirect, session, url_for, send_file
from database.database import get_connection, init_database
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import date, datetime, timedelta
from werkzeug.utils import secure_filename
import os
import csv
import io
import re
import secrets
import smtplib
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = os.environ.get("LIBRARY_SECRET_KEY") or "DEV-ONLY-change-this-secret-key"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("LIBRARY_HTTPS", "0") == "1"
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

# Ensure all tables and migrations exist before the first request.
init_database()

def _repair_book_image_storage():
    """Move legacy book covers into the canonical uploads/books folder."""
    conn = get_connection()
    rows = conn.execute("SELECT id, image FROM books WHERE image IS NOT NULL AND image != ''").fetchall()
    changed = False
    book_folder = os.path.join(app.root_path, "static", "uploads", "books")
    legacy_folder = os.path.join(app.root_path, "static", "uploads")
    os.makedirs(book_folder, exist_ok=True)
    import shutil
    for row in rows:
        src = os.path.join(legacy_folder, row["image"])
        dst = os.path.join(book_folder, row["image"])
        if os.path.exists(src) and not os.path.exists(dst):
            try:
                shutil.move(src, dst)
                changed = True
            except OSError:
                pass
    if changed: conn.commit()
    conn.close()

STUDENT_UPLOAD_FOLDER = os.path.join(
    app.root_path, "static", "uploads", "students"
)

os.makedirs(STUDENT_UPLOAD_FOLDER, exist_ok=True)
for _media_folder in (
    os.path.join(app.root_path, "static", "uploads", "books"),
    os.path.join(app.root_path, "static", "uploads", "admins"),
    os.path.join(app.root_path, "static", "uploads", "events"),
    os.path.join(app.root_path, "static", "uploads", "magazines", "covers"),
    os.path.join(app.root_path, "static", "uploads", "magazines", "pdfs"),
):
    os.makedirs(_media_folder, exist_ok=True)
_repair_book_image_storage()

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _log_activity(conn, action, description, librarian_id=None):
    try:
        lid = librarian_id
        if librarian_id is not None:
            row = conn.execute("SELECT id FROM librarians WHERE user_id=?", (librarian_id,)).fetchone()
            if row: lid = row["id"]
        conn.execute(
            "INSERT INTO librarian_activity(librarian_id, action, description) VALUES (?, ?, ?)",
            (lid, action, description),
        )
    except Exception:
        # Activity logging must never break the primary library operation.
        pass

def _notify_students(conn, message):
    students = conn.execute("SELECT user_id FROM students WHERE user_id IS NOT NULL").fetchall()
    for row in students:
        conn.execute(
            "INSERT INTO notifications(user_id, message, is_read) VALUES (?, ?, 0)",
            (row["user_id"], message),
        )

def _current_fine(due_date, status="Issued", stored_fine=0):
    if status == "Issued" and due_date:
        try:
            late_days = (date.today() - date.fromisoformat(due_date)).days
            return max(0, late_days) * 5
        except (TypeError, ValueError):
            return stored_fine or 0
    return stored_fine or 0


def _strong_password(password):
    return (len(password) >= 10 and any(c.isalpha() for c in password)
            and any(c.isdigit() for c in password))

def _normalize_phone(phone):
    phone = re.sub(r"[^0-9+]", "", phone or "")
    if phone.startswith("0") and len(phone) == 10:
        phone = "+91" + phone
    if phone.startswith("91") and len(phone) == 12:
        phone = "+" + phone
    return phone

def _send_sms_otp(phone):
    phone = _normalize_phone(phone)
    sid = os.environ.get("TWILIO_ACCOUNT_SID")
    token = os.environ.get("TWILIO_AUTH_TOKEN")
    service = os.environ.get("TWILIO_VERIFY_SERVICE_SID")
    if not (sid and token and service):
        return False, "SMS service is not configured. Add Twilio Verify environment variables."
    try:
        from twilio.rest import Client
        client = Client(sid, token)
        client.verify.v2.services(service).verifications.create(to=phone, channel="sms")
        return True, "SMS OTP sent."
    except Exception as exc:
        return False, f"Unable to send SMS OTP: {exc}"

def _check_sms_otp(phone, code):
    sid = os.environ.get("TWILIO_ACCOUNT_SID")
    token = os.environ.get("TWILIO_AUTH_TOKEN")
    service = os.environ.get("TWILIO_VERIFY_SERVICE_SID")
    if not (sid and token and service):
        return False, "SMS service is not configured."
    try:
        from twilio.rest import Client
        client = Client(sid, token)
        result = client.verify.v2.services(service).verification_checks.create(
            to=_normalize_phone(phone), code=code.strip()
        )
        return result.status == "approved", "Phone verification complete." if result.status == "approved" else "Invalid or expired OTP."
    except Exception as exc:
        return False, f"Unable to verify SMS OTP: {exc}"

def _send_email_otp(email, otp):
    host=os.environ.get("SMTP_HOST"); port=int(os.environ.get("SMTP_PORT", "587")); user=os.environ.get("SMTP_USER"); password=os.environ.get("SMTP_PASSWORD"); sender=os.environ.get("SMTP_FROM", user or "")
    if not (host and user and password and sender):
        return False, "Email service is not configured."
    try:
        msg=EmailMessage(); msg["Subject"]="Library Management System email verification"; msg["From"]=sender; msg["To"]=email
        msg.set_content(f"Your Library Management System verification code is {otp}. It expires in 10 minutes.")
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls(); server.login(user,password); server.send_message(msg)
        return True, "Email OTP sent."
    except Exception as exc:
        return False, f"Unable to send email OTP: {exc}"


@app.after_request
def _no_cache_html(response):
    # Prevent browsers from keeping an old template/loader after a project update.
    if response.content_type and response.content_type.startswith("text/html"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


@app.before_request
def _student_security_gate():
    if request.endpoint in {"login", "student_register", "forgot_password", "verify_otp", "verify_contact", "change_password", "static", "health", "logout"}:
        return None
    if session.get("role") == "student":
        try:
            conn=get_connection(); user=conn.execute("SELECT must_change_password,email_verified,phone_verified FROM users WHERE id=?",(session.get("user_id"),)).fetchone(); conn.close()
            if not user: return None
            if user["must_change_password"]: return redirect(url_for("change_password"))
            if not user["email_verified"] or not user["phone_verified"]:
                return redirect(url_for("verify_contact"))
        except Exception:
            return None
    return None

@app.route("/health")
def health():
    try:
        conn=get_connection()
        counts={t:conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("users","students","librarians","books","issues","ebooks","journals","magazines","events","notices")}
        conn.close()
        return jsonify({"success":True,"status":"ok","database":"connected","counts":counts})
    except Exception as exc:
        return jsonify({"success":False,"status":"error","message":str(exc)}),500


# =========================
# HOME
# =========================

# =========================
# STUDENT DASHBOARD
# =========================

@app.route("/student")
def student_dashboard():

    if "user_id" not in session or session["role"] != "student":
        return redirect(url_for("login"))

    conn = get_connection()
    student = conn.execute("""
        SELECT * FROM students WHERE user_id = ?
    """, (session["user_id"],)).fetchone()
    total_books = conn.execute("SELECT COUNT(*) FROM books").fetchone()[0]
    issued_books = conn.execute("""
        SELECT COUNT(*) FROM issues i
        JOIN students s ON s.id = i.student_id
        WHERE s.user_id = ? AND i.status = 'Issued'
    """, (session["user_id"],)).fetchone()[0]
    total_ebooks = conn.execute("SELECT COUNT(*) FROM ebooks").fetchone()[0]
    total_journals = conn.execute("SELECT COUNT(*) FROM journals").fetchone()[0]
    total_magazines = conn.execute("SELECT COUNT(*) FROM magazines").fetchone()[0]
    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_notices = conn.execute("SELECT COUNT(*) FROM notices").fetchone()[0]
    unread_notifications = conn.execute("""
        SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0
    """, (session["user_id"],)).fetchone()[0]
    conn.close()
    return render_template(
        "student_dashboard.html",
        name=session["full_name"],
        student=student,
        total_books=total_books,
        issued_books=issued_books,
        total_ebooks=total_ebooks,
        total_journals=total_journals,
        total_magazines=total_magazines,
        total_events=total_events,
        total_notices=total_notices,
        unread_notifications=unread_notifications
    )

@app.route("/")
def home():

    if "user_id" not in session:
        return redirect(url_for("login"))

    role = session["role"]

    if role == "admin":
        return redirect(url_for("admin_dashboard"))

    if role == "librarian":
        return redirect(url_for("librarian_dashboard"))

    if role == "student":
        return redirect(url_for("student_dashboard"))

    return redirect(url_for("logout"))


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_connection()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            if user["role"] == "student":
                if user["must_change_password"]:
                    return redirect(url_for("change_password"))
                if (user["email"] and not user["email_verified"]) or (user["phone"] and not user["phone_verified"]):
                    return redirect(url_for("verify_contact"))
            return redirect(url_for("home"))

        error = "Invalid username or password."

    return render_template("login.html", error=error)



# =========================
# STUDENT REGISTRATION
# =========================

@app.route("/student/register", methods=["GET", "POST"])
def student_register():

    error = None

    if request.method == "POST":

        full_name = request.form["full_name"].strip()
        roll_no = request.form["roll_no"].strip().upper()
        course = request.form["course"].strip()
        semester = request.form["semester"].strip()
        academic_year = request.form["academic_year"].strip()
        email = request.form.get("email", "").strip()
        phone = _normalize_phone(request.form.get("phone", "").strip())
        profile_image = request.files.get("profile_image")
        profile_image_name = None

        if profile_image and profile_image.filename:
            profile_image_name = secure_filename(profile_image.filename)
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Accept both legacy roll numbers and newer college register numbers.
        if not roll_no:
            error = "Register number is required."

        elif password != confirm_password:
            error = "Passwords do not match."

        elif not _strong_password(password):
            error = "Password must contain at least 10 characters with letters and numbers."

        else:
            conn = get_connection()

            existing_user = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            existing_student = conn.execute(
                "SELECT id FROM students WHERE roll_no = ?",
                (roll_no,)
            ).fetchone()

            if existing_user:
                error = "Username already exists."

            elif existing_student:
                error = "This register number is already registered."

            else:
                hashed_password = generate_password_hash(password)

                cursor = conn.execute(
                    """
                    INSERT INTO users
                    (username, password, full_name, role, email, phone, must_change_password, email_verified, phone_verified)
                    VALUES (?, ?, ?, 'student', ?, ?, 0, 0, 0)
                    """,
                    (username, hashed_password, full_name, email, phone)
                )

                user_id = cursor.lastrowid

                conn.execute(
                    """
                    INSERT INTO students
                    (user_id, roll_no, course, semester, academic_year)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (user_id, roll_no, course, semester, academic_year)
                )

                conn.commit()

                # Save student profile photo
                if profile_image and profile_image.filename:
                    extension = os.path.splitext(
                        profile_image_name
                    )[1].lower()

                    allowed_extensions = {
                        ".jpg", ".jpeg", ".png", ".webp"
                    }

                    if extension in allowed_extensions:
                        filename = f"student_{user_id}{extension}"

                        profile_image.save(
                            os.path.join(
                                STUDENT_UPLOAD_FOLDER,
                                filename
                            )
                        )

                        conn.execute(
                            """
                            UPDATE students
                            SET profile_image = ?
                            WHERE user_id = ?
                            """,
                            (filename, user_id)
                        )

                        conn.commit()

                conn.close()

                return redirect(url_for("login"))

            conn.close()

    return render_template("student_register.html", error=error)



# =========================
# INVITE STUDENTS
# =========================

@app.route("/admin/invite-students")
def invite_students():

    if "user_id" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    invite_link = request.url_root.rstrip("/") + url_for("student_register")

    return render_template(
        "invite_students.html",
        invite_link=invite_link
    )



# =========================
# COLLEGE MAGAZINES
# =========================

ALLOWED_MAGAZINE_IMAGES = {".jpg", ".jpeg", ".png", ".webp"}
ALLOWED_MAGAZINE_PDFS = {".pdf"}


@app.route("/magazines")
def magazines():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_connection()

    magazines = conn.execute("""
        SELECT
            id,
            title,
            description,
            academic_year,
            semester,
            department,
            publication_date,
            cover_image,
            pdf_file
        FROM magazines
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "magazines.html",
        magazines=magazines
    )


@app.route("/admin/magazines")
def manage_magazines():

    if "user_id" not in session or session["role"] not in ["admin", "librarian"]:
        return redirect(url_for("login"))

    conn = get_connection()

    magazines = conn.execute("""
        SELECT *
        FROM magazines
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "manage_magazines.html",
        magazines=magazines
    )


@app.route("/admin/magazines/add", methods=["GET", "POST"])
def add_magazine():

    if "user_id" not in session or session["role"] not in ["admin", "librarian"]:
        return redirect(url_for("login"))

    error = None

    if request.method == "POST":

        title = request.form["title"].strip()
        description = request.form.get("description", "").strip()
        academic_year = request.form.get("academic_year", "").strip()
        semester = request.form.get("semester", "").strip()
        department = request.form.get("department", "").strip()
        publication_date = request.form.get("publication_date", "").strip()

        cover = request.files.get("cover_image")
        pdf = request.files.get("pdf_file")

        if not title:
            error = "Magazine title is required."

        elif not pdf or not pdf.filename:
            error = "Magazine PDF is required."

        else:

            import os
            from werkzeug.utils import secure_filename

            pdf_name = secure_filename(pdf.filename)
            pdf_ext = os.path.splitext(pdf_name)[1].lower()

            if pdf_ext not in ALLOWED_MAGAZINE_PDFS:
                error = "Only PDF files are allowed."

            else:

                cover_name = None

                if cover and cover.filename:

                    cover_original = secure_filename(cover.filename)
                    cover_ext = os.path.splitext(cover_original)[1].lower()

                    if cover_ext not in ALLOWED_MAGAZINE_IMAGES:
                        error = "Invalid cover image format."
                    else:
                        import uuid

                        cover_name = (
                            f"magazine_{uuid.uuid4().hex}{cover_ext}"
                        )

                if not error:

                    import uuid

                    pdf_name = (
                        f"magazine_{uuid.uuid4().hex}.pdf"
                    )

                    cover_path = None

                    if cover_name:
                        cover_path = os.path.join(app.root_path, "static", "uploads", "magazines", "covers", cover_name)
                        os.makedirs(os.path.dirname(cover_path), exist_ok=True)
                        cover.save(cover_path)

                    pdf_path = os.path.join(app.root_path, "static", "uploads", "magazines", "pdfs", pdf_name)
                    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
                    pdf.save(pdf_path)

                    conn = get_connection()

                    conn.execute("""
                        INSERT INTO magazines
                        (
                            title,
                            description,
                            academic_year,
                            semester,
                            department,
                            publication_date,
                            cover_image,
                            pdf_file,
                            uploaded_by
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        title,
                        description,
                        academic_year,
                        int(semester) if semester.isdigit() else None,
                        department,
                        publication_date,
                        cover_name,
                        pdf_name,
                        session["user_id"]
                    ))

                    conn.commit()
                    conn.close()

                    return redirect(url_for("manage_magazines"))

    return render_template(
        "add_magazine.html",
        error=error
    )


@app.route("/admin/magazines/delete/<int:magazine_id>", methods=["POST"])
def delete_magazine(magazine_id):

    if "user_id" not in session or session["role"] not in ["admin", "librarian"]:
        return redirect(url_for("login"))

    conn = get_connection()

    magazine = conn.execute("""
        SELECT cover_image, pdf_file
        FROM magazines
        WHERE id = ?
    """, (magazine_id,)).fetchone()

    if magazine:

        import os

        if magazine["cover_image"]:
            path = os.path.join(app.root_path, "static", "uploads", "magazines", "covers", magazine["cover_image"])
            if os.path.exists(path):
                os.remove(path)

        if magazine["pdf_file"]:
            path = os.path.join(app.root_path, "static", "uploads", "magazines", "pdfs", magazine["pdf_file"])
            if os.path.exists(path):
                os.remove(path)

        conn.execute(
            "DELETE FROM magazines WHERE id = ?",
            (magazine_id,)
        )

        conn.commit()

    conn.close()

    return redirect(url_for("manage_magazines"))


# =========================
# ADMIN DIRECTORY DETAILS
# =========================
@app.route("/admin/students/<int:student_id>")
def admin_student_profile(student_id):
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    conn = get_connection()
    student = conn.execute("""
        SELECT students.*, users.full_name, users.username, users.email, users.phone
        FROM students JOIN users ON users.id = students.user_id
        WHERE students.id = ?
    """, (student_id,)).fetchone()
    books = conn.execute("""
        SELECT books.title, books.author, issues.issue_date, issues.due_date, issues.return_date, issues.status, issues.fine
        FROM issues JOIN books ON books.id = issues.book_id
        WHERE issues.student_id = ? ORDER BY issues.id DESC
    """, (student_id,)).fetchall() if student else []
    conn.close()
    if not student:
        return "Student not found", 404
    return render_template("admin_student_profile.html", student=student, books=books)

@app.route("/admin/librarians/<int:librarian_id>")
def admin_librarian_profile(librarian_id):
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    conn = get_connection()
    librarian = conn.execute("""
        SELECT librarians.*, users.full_name, users.username, users.email, users.phone, users.profile_image
        FROM librarians JOIN users ON users.id = librarians.user_id
        WHERE librarians.id = ?
    """, (librarian_id,)).fetchone()
    conn.close()
    if not librarian:
        return "Librarian not found", 404
    return render_template("admin_librarian_profile.html", librarian=librarian)

# =========================
# ADMIN DASHBOARD
# =========================
@app.route("/admin")
def admin_dashboard():

    if "user_id" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_connection()

    total_books = conn.execute(
        "SELECT COUNT(*) FROM books"
    ).fetchone()[0]

    total_students = conn.execute(
        "SELECT COUNT(*) FROM students"
    ).fetchone()[0]

    total_librarians = conn.execute(
        "SELECT COUNT(*) FROM librarians"
    ).fetchone()[0]

    issued_books = conn.execute("""
        SELECT COUNT(*) FROM issues WHERE status = 'Issued'
    """).fetchone()[0]
    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_ebooks = conn.execute("SELECT COUNT(*) FROM ebooks").fetchone()[0]
    total_journals = conn.execute("SELECT COUNT(*) FROM journals").fetchone()[0]
    total_magazines = conn.execute("SELECT COUNT(*) FROM magazines").fetchone()[0]
    overdue_count = conn.execute("""
        SELECT COUNT(*) FROM issues
        WHERE status = 'Issued' AND due_date IS NOT NULL AND date(due_date) < date('now')
    """).fetchone()[0]
    total_fine = conn.execute("""
        SELECT COALESCE(SUM(
            CASE WHEN status='Issued' AND due_date IS NOT NULL AND date(due_date) < date('now')
                 THEN (julianday(date('now')) - julianday(date(due_date))) * 5
                 ELSE COALESCE(fine,0) END
        ),0) FROM issues
    """).fetchone()[0]

    conn.close()

    return render_template(
        "admin_dashboard.html",
        name=session["full_name"],
        total_books=total_books,
        total_students=total_students,
        total_librarians=total_librarians,
        issued_books=issued_books,
        total_events=total_events,
        total_ebooks=total_ebooks,
        total_journals=total_journals,
        total_magazines=total_magazines,
        overdue_count=overdue_count,
        total_fine=round(total_fine or 0, 2)
    )
# =========================
# USER MANAGEMENT
# =========================

@app.route("/admin/users")
def manage_users():

    if "user_id" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_connection()

    users = conn.execute("""
        SELECT
            id,
            username,
            full_name,
            role
        FROM users
        ORDER BY role, full_name
    """).fetchall()

    conn.close()

    return render_template(
        "manage_users.html",
        users=users
    )

# =========================
# STUDENT MANAGEMENT
# =========================

@app.route("/admin/students")
def manage_students():

    if "user_id" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_connection()

    students = conn.execute("""
        SELECT
            students.id,
            users.id AS user_id,
            users.full_name,
            users.username,
            students.roll_no,
            students.course,
            students.semester,
            students.academic_year,
            students.profile_image
        FROM users
        JOIN students ON users.id = students.user_id
        ORDER BY users.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "manage_students.html",
        students=students
    )


@app.route("/admin/students/add", methods=["GET", "POST"])
def add_student():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    error = None; generated_password = None
    if request.method == "POST":
        name=request.form.get("full_name","").strip(); username=request.form.get("username","").strip()
        password=request.form.get("password","").strip() or secrets.token_urlsafe(9)
        roll_no=request.form.get("roll_no","").strip().upper(); course=request.form.get("course","").strip()
        semester=request.form.get("semester","").strip() or None; academic_year=request.form.get("academic_year","").strip() or "2026-27"
        department=request.form.get("department","").strip(); email=request.form.get("email","").strip(); phone=_normalize_phone(request.form.get("phone","").strip())
        if not name or not username or not roll_no or not course:
            error="Please fill all required fields."
        elif not _strong_password(password):
            error="Password must contain at least 10 characters with letters and numbers."
        else:
            conn=get_connection()
            try:
                cur=conn.execute("INSERT INTO users(username,password,full_name,role,email,phone,must_change_password,email_verified,phone_verified) VALUES(?,?,?,?,?,?,?,?,?)",(username,generate_password_hash(password),name,"student",email,phone,1,0,0))
                conn.execute("INSERT INTO students(user_id,roll_no,course,semester,academic_year,department) VALUES(?,?,?,?,?,?)",(cur.lastrowid,roll_no,course,int(semester) if semester and semester.isdigit() else None,academic_year,department))
                conn.commit(); generated_password=password if not request.form.get("password") else None
                conn.close()
                return render_template("add_student.html", success="Student created successfully.", generated_password=generated_password, created_username=username)
            except Exception:
                conn.rollback(); conn.close(); error="Username or Roll Number already exists."
    return render_template("add_student.html", error=error)

@app.route("/admin/students/import", methods=["GET", "POST"])
def import_students():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    error=None; result_file=None; imported=[]
    if request.method=="POST":
        upload=request.files.get("csv_file")
        if not upload or not upload.filename.lower().endswith(".csv"):
            error="Please upload a CSV file."
        else:
            conn=get_connection()
            try:
                text=upload.read().decode("utf-8-sig")
                reader=csv.DictReader(io.StringIO(text))
                required={"full_name","username","roll_no","course"}
                if not required.issubset({(x or "").strip() for x in (reader.fieldnames or [])}):
                    raise ValueError("CSV must contain full_name, username, roll_no and course columns.")
                for row in reader:
                    name=(row.get("full_name") or "").strip(); username=(row.get("username") or "").strip(); roll=(row.get("roll_no") or "").strip().upper(); course=(row.get("course") or "").strip()
                    if not name or not username or not roll or not course: continue
                    if conn.execute("SELECT 1 FROM users WHERE username=?",(username,)).fetchone() or conn.execute("SELECT 1 FROM students WHERE roll_no=?",(roll,)).fetchone(): continue
                    temp=secrets.token_urlsafe(9)
                    cur=conn.execute("INSERT INTO users(username,password,full_name,role,email,phone,must_change_password,email_verified,phone_verified) VALUES(?,?,?,?,?,?,?,?,?)",(username,generate_password_hash(temp),name,"student",(row.get("email") or "").strip(),_normalize_phone((row.get("phone") or "").strip()),1,0,0))
                    sem=(row.get("semester") or "").strip(); conn.execute("INSERT INTO students(user_id,roll_no,course,semester,academic_year,department) VALUES(?,?,?,?,?,?)",(cur.lastrowid,roll,course,int(sem) if sem.isdigit() else None,(row.get("academic_year") or "2026-27").strip(),(row.get("department") or "").strip()))
                    imported.append((name,username,temp,roll))
                conn.commit()
                out=io.StringIO(); writer=csv.writer(out); writer.writerow(["full_name","username","temporary_password","roll_no"]); writer.writerows(imported)
                result_file=out.getvalue()
            except Exception as exc:
                conn.rollback(); error=str(exc)
            finally: conn.close()
    return render_template("import_students.html",error=error,imported_count=len(imported),result_file=result_file)



# =========================
# EDIT STUDENT
# =========================

# =========================
# DELETE STUDENT
# =========================
@app.route("/admin/students/delete/<int:student_id>", methods=["POST"])
def delete_student(student_id):
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn=get_connection()
    student=conn.execute("SELECT user_id,profile_image FROM students WHERE id=?",(student_id,)).fetchone()
    if not student:
        conn.close(); return redirect(url_for("manage_students"))
    active=conn.execute("SELECT book_id,COUNT(*) AS n FROM issues WHERE student_id=? AND status='Issued' GROUP BY book_id",(student_id,)).fetchall()
    for row in active:
        conn.execute("UPDATE books SET quantity=quantity+? WHERE id=?",(row["n"],row["book_id"]))
    conn.execute("DELETE FROM issues WHERE student_id=?",(student_id,))
    conn.execute("DELETE FROM reservations WHERE student_id=?",(student_id,))
    conn.execute("DELETE FROM notifications WHERE user_id=?",(student["user_id"],))
    conn.execute("DELETE FROM digital_bookmarks WHERE user_id=?",(student["user_id"],))
    conn.execute("DELETE FROM digital_read_history WHERE user_id=?",(student["user_id"],))
    conn.execute("DELETE FROM students WHERE id=?",(student_id,))
    conn.execute("DELETE FROM users WHERE id=?",(student["user_id"],))
    conn.commit(); conn.close()
    if student["profile_image"]:
        path=os.path.join(app.root_path,"static","uploads","students",student["profile_image"])
        if os.path.exists(path):
            try: os.remove(path)
            except OSError: pass
    return redirect(url_for("manage_students"))

@app.route("/admin/students/edit/<int:student_id>", methods=["GET", "POST"])
def edit_student(student_id):
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    conn=get_connection()
    student=conn.execute("""
        SELECT s.*,u.full_name,u.username,u.email,u.phone
        FROM students s JOIN users u ON u.id=s.user_id WHERE s.id=?
    """,(student_id,)).fetchone()
    if not student:
        conn.close(); return "Student not found",404
    if request.method=="POST":
        full_name=request.form.get("full_name","").strip(); username=request.form.get("username","").strip()
        roll_no=request.form.get("roll_no","").strip().upper(); course=request.form.get("course","").strip()
        semester=request.form.get("semester","").strip() or None; academic_year=request.form.get("academic_year","").strip() or "2026-27"
        department=request.form.get("department","").strip(); password=request.form.get("password","")
        email=request.form.get("email","").strip(); phone=_normalize_phone(request.form.get("phone","").strip())
        if not full_name or not username or not roll_no or not course:
            conn.close(); return render_template("edit_student.html",student=student,error="Please fill in all required fields.")
        try:
            conn.execute("UPDATE users SET full_name=?,username=?,email=?,phone=?,email_verified=CASE WHEN email=? THEN email_verified ELSE 0 END,phone_verified=CASE WHEN phone=? THEN phone_verified ELSE 0 END WHERE id=?",(full_name,username,email,phone,email,phone,student["user_id"]))
            conn.execute("UPDATE students SET roll_no=?,course=?,semester=?,academic_year=?,department=? WHERE id=?",(roll_no,course,int(semester) if semester and semester.isdigit() else None,academic_year,department,student_id))
            if password.strip():
                if not _strong_password(password):
                    raise ValueError("Password must contain at least 10 characters with letters and numbers.")
                conn.execute("UPDATE users SET password=?,must_change_password=1 WHERE id=?",(generate_password_hash(password),student["user_id"]))
            conn.commit(); conn.close(); return redirect(url_for("manage_students"))
        except ValueError as exc:
            conn.rollback(); conn.close(); return render_template("edit_student.html",student=student,error=str(exc))
        except Exception:
            conn.rollback(); conn.close(); return render_template("edit_student.html",student=student,error="Username or Roll Number already exists.")
    conn.close(); return render_template("edit_student.html",student=student)


# =========================
# LIBRARIAN MANAGEMENT
# =========================

@app.route("/admin/librarians")
def manage_librarians():

    if "user_id" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    conn = get_connection()

    librarians = conn.execute("""
        SELECT
            librarians.id AS librarian_id,
            users.id AS user_id,
            users.full_name,
            users.username,
            librarians.employee_id
        FROM users
        JOIN librarians ON users.id = librarians.user_id
        ORDER BY users.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "manage_librarians.html",
        librarians=librarians
    )


@app.route("/admin/librarians/add", methods=["GET", "POST"])
def add_librarian():

    if "user_id" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":

        name = request.form["full_name"].strip()
        username = request.form["username"].strip()
        password = request.form["password"]
        employee_id = request.form["employee_id"].strip()

        conn = get_connection()

        try:

            cursor = conn.execute("""
                INSERT INTO users
                (username, password, full_name, role)
                VALUES (?, ?, ?, ?)
            """, (
                username,
                generate_password_hash(password),
                name,
                "librarian"
            ))

            user_id = cursor.lastrowid

            conn.execute("""
                INSERT INTO librarians
                (user_id, employee_id)
                VALUES (?, ?)
            """, (
                user_id,
                employee_id
            ))

            conn.commit()

        except Exception:

            conn.rollback()
            conn.close()

            return render_template(
                "add_librarian.html",
                error="Username or Employee ID already exists."
            )

        conn.close()

        return redirect(url_for("manage_librarians"))

    return render_template("add_librarian.html")


# =========================
# BOOK MANAGEMENT
# =========================

@app.route("/admin/books")
def manage_books():

    if "user_id" not in session or session["role"] not in ("admin", "librarian"):
        return redirect(url_for("login"))

    conn = get_connection()

    books = conn.execute("""
        SELECT *
        FROM books
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "manage_books.html",
        books=books,
        error=request.args.get("error")
    )


@app.route("/admin/books/add", methods=["GET", "POST"])
def add_book():

    if "user_id" not in session or session["role"] not in ("admin", "librarian"):
        return redirect(url_for("login"))

    if request.method == "POST":

        title = request.form.get("title", "").strip()
        author = request.form.get("author", "").strip()
        category = request.form.get("category", "").strip()
        isbn = request.form.get("isbn", "").strip()
        quantity_raw = request.form.get("quantity", "1").strip()
        error = None
        try:
            quantity = max(0, int(quantity_raw))
        except ValueError:
            quantity = 0
            error = "Quantity must be a valid number."

        if not title or not author:
            error = "Book title and author are required."

        image = request.files.get("event_image")
        image_filename = None

        if image and image.filename and not error:
            upload_folder = os.path.join(app.root_path, "static", "uploads", "books")
            os.makedirs(upload_folder, exist_ok=True)
            filename = secure_filename(image.filename)
            ext = os.path.splitext(filename)[1].lower()
            if ext in ALLOWED_IMAGE_EXT:
                import uuid
                image_filename = f"book_{uuid.uuid4().hex}{ext}"
                image.save(os.path.join(upload_folder, image_filename))
            else:
                error = "Use JPG, PNG or WEBP for book images."

        if error:
            return render_template("add_book.html", error=error)

        conn = get_connection()
        conn.execute("""
            INSERT INTO books (title, author, category, isbn, quantity, image)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (title, author, category, isbn, quantity, image_filename))
        conn.commit()
        conn.close()
        return redirect(url_for("manage_books"))

    return render_template("add_book.html")


@app.route("/admin/books/edit/<int:book_id>", methods=["GET", "POST"])
def edit_book(book_id):

    if "user_id" not in session or session["role"] not in ("admin", "librarian"):
        return redirect(url_for("login"))

    conn = get_connection()

    book = conn.execute(
        "SELECT * FROM books WHERE id = ?",
        (book_id,)
    ).fetchone()

    if not book:
        conn.close()
        return "Book not found", 404

    if request.method == "POST":

        title = request.form.get("title", "").strip()
        author = request.form.get("author", "").strip()
        category = request.form.get("category", "").strip()
        isbn = request.form.get("isbn", "").strip()
        quantity_raw = request.form.get("quantity", "0").strip()
        try:
            quantity = max(0, int(quantity_raw))
        except ValueError:
            conn.close()
            return render_template("edit_book.html", book=book, error="Quantity must be a valid number.")
        if not title or not author:
            conn.close()
            return render_template("edit_book.html", book=book, error="Book title and author are required.")

        image = request.files.get("image")
        gallery_image = request.files.get("image_gallery")

        if gallery_image and gallery_image.filename:
            image = gallery_image

        image_filename = book["image"]

        if image and image.filename:
            import os
            from werkzeug.utils import secure_filename

            upload_folder = os.path.join(
                app.root_path,
                "static",
                "uploads",
                "books"
            )

            os.makedirs(upload_folder, exist_ok=True)

            filename = secure_filename(image.filename)
            ext = os.path.splitext(filename)[1].lower()
            if ext not in ALLOWED_IMAGE_EXT:
                conn.close()
                return render_template("edit_book.html", book=book, error="Use JPG, PNG or WEBP for book images.")
            import uuid
            filename = f"book_{book_id}_{uuid.uuid4().hex}{ext}"
            image.save(os.path.join(upload_folder, filename))
            image_filename = filename

        conn.execute("""
            UPDATE books
            SET title = ?,
                author = ?,
                category = ?,
                isbn = ?,
                quantity = ?,
                image = ?
            WHERE id = ?
        """, (
            title,
            author,
            category,
            isbn,
            quantity,
            image_filename,
            book_id
        ))

        conn.commit()
        conn.close()

        return redirect(url_for("manage_books"))

    conn.close()

    return render_template(
        "edit_book.html",
        book=book
    )


@app.route("/admin/books/delete/<int:book_id>", methods=["POST"])
def delete_book(book_id):
    if "user_id" not in session or session["role"] not in ("admin", "librarian"):
        return redirect(url_for("login"))

    conn = get_connection()
    book = conn.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
    if not book:
        conn.close()
        return redirect(url_for("manage_books"))

    active = conn.execute("SELECT COUNT(*) FROM issues WHERE book_id=? AND status='Issued'", (book_id,)).fetchone()[0]
    if active:
        conn.close()
        return render_template("manage_books.html", books=[book], error="This book cannot be deleted while it is issued. Return all active copies first.")

    # Remove dependent records first, then the catalog item.
    conn.execute("DELETE FROM reservations WHERE book_id=?", (book_id,))
    conn.execute("DELETE FROM digital_bookmarks WHERE resource_type='book' AND resource_id=?", (book_id,))
    conn.execute("DELETE FROM books WHERE id=?", (book_id,))
    conn.commit()
    conn.close()

    image_name = book["image"]
    if image_name:
        for folder in (
            os.path.join(app.root_path, "static", "uploads", "books"),
            os.path.join(app.root_path, "static", "uploads"),
        ):
            path = os.path.join(folder, image_name)
            if os.path.exists(path):
                try: os.remove(path)
                except OSError: pass
    return redirect(url_for("manage_books"))

# =========================
# STUDENT BOOK SEARCH
# =========================

@app.route("/student/books")
def student_books():

    if "user_id" not in session or session["role"] != "student":
        return redirect(url_for("login"))

    search = request.args.get("search", "").strip()

    conn = get_connection()

    if search:

        books = conn.execute("""
            SELECT *
            FROM books
            WHERE title LIKE ?
               OR author LIKE ?
               OR category LIKE ?
               OR isbn LIKE ?
            ORDER BY title
        """, (
            "%" + search + "%",
            "%" + search + "%",
            "%" + search + "%",
            "%" + search + "%"
        )).fetchall()

    else:

        books = conn.execute("""
            SELECT *
            FROM books
            ORDER BY title
        """).fetchall()

    conn.close()

    return render_template(
        "student_books.html",
        books=books,
        search=search
    )


# =========================
# LIBRARIAN DASHBOARD
# =========================

@app.route("/librarian/students")
def librarian_manage_students():
    if "user_id" not in session or session.get("role") != "librarian":
        return redirect(url_for("login"))
    conn=get_connection()
    students=conn.execute("""
        SELECT students.id, users.full_name, users.username, students.roll_no, students.course,
               students.semester, students.academic_year, students.department, students.profile_image
        FROM students JOIN users ON users.id=students.user_id
        ORDER BY users.full_name
    """).fetchall()
    conn.close()
    return render_template("librarian_students.html", students=students)

@app.route("/librarian/students/add", methods=["GET","POST"])
def librarian_add_student():
    if "user_id" not in session or session.get("role") != "librarian":
        return redirect(url_for("login"))
    if request.method == "POST":
        name=request.form.get("full_name","").strip()
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        roll_no=request.form.get("roll_no","").strip()
        course=request.form.get("course","").strip()
        semester=request.form.get("semester","").strip() or None
        academic_year=request.form.get("academic_year","").strip()
        department=request.form.get("department","").strip()
        conn=get_connection()
        try:
            cur=conn.execute("INSERT INTO users(username,password,full_name,role) VALUES(?,?,?,?)",(username,generate_password_hash(password),name,"student"))
            conn.execute("INSERT INTO students(user_id,roll_no,course,semester,academic_year,department) VALUES(?,?,?,?,?,?)",(cur.lastrowid,roll_no,course,semester,academic_year,department))
            conn.commit()
        except Exception:
            conn.rollback(); conn.close()
            return render_template("add_student.html", error="Username or Roll Number already exists.")
        conn.close()
        return redirect(url_for("librarian_manage_students"))
    return render_template("add_student.html")

@app.route("/librarian")
def librarian_dashboard():

    if "user_id" not in session or session["role"] != "librarian":
        return redirect(url_for("login"))

    conn = get_connection()
    stats = {
        "books": conn.execute("SELECT COUNT(*) FROM books").fetchone()[0],
        "students": conn.execute("SELECT COUNT(*) FROM students").fetchone()[0],
        "issued": conn.execute("SELECT COUNT(*) FROM issues WHERE status='Issued'").fetchone()[0],
        "ebooks": conn.execute("SELECT COUNT(*) FROM ebooks").fetchone()[0],
        "journals": conn.execute("SELECT COUNT(*) FROM journals").fetchone()[0],
        "magazines": conn.execute("SELECT COUNT(*) FROM magazines").fetchone()[0],
        "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
    }
    conn.close()
    return render_template("librarian_dashboard.html", name=session["full_name"], stats=stats)


# =========================
# ISSUE BOOK
# =========================

# =========================
# ISSUE BOOK
# =========================

@app.route("/librarian/issue", methods=["GET", "POST"])
def issue_book():

    if "user_id" not in session or session["role"] != "librarian":
        return redirect(url_for("login"))

    conn = get_connection()
    error = None

    if request.method == "POST":

        book_id = request.form.get("book_id")
        student_id = request.form.get("student_id")
        due_date = request.form.get("due_date")

        book = conn.execute(
            "SELECT * FROM books WHERE id = ?",
            (book_id,)
        ).fetchone()

        student = conn.execute(
            "SELECT * FROM students WHERE id = ?",
            (student_id,)
        ).fetchone()

        if not book:
            error = "Book not found."

        elif not student:
            error = "Student not found."

        elif book["quantity"] <= 0:
            error = "This book is currently unavailable."

        elif not due_date:
            error = "Please select a due date."
        elif conn.execute("SELECT 1 FROM issues WHERE book_id=? AND student_id=? AND status='Issued'", (book_id, student_id)).fetchone():
            error = "This student already has this book issued."
        else:

            today = date.today().isoformat()

            librarian_row = conn.execute("SELECT id FROM librarians WHERE user_id=?", (session["user_id"],)).fetchone()
            conn.execute("""
                INSERT INTO issues
                (book_id, student_id, issue_date, due_date, status, fine, librarian_id)
                VALUES (?, ?, ?, ?, 'Issued', 0, ?)
            """, (book_id, student_id, today, due_date, librarian_row["id"] if librarian_row else None))

            conn.execute("""
                UPDATE books
                SET quantity = quantity - 1
                WHERE id = ?
            """, (book_id,))

            # Complete the approved reservation
            conn.execute("""
                UPDATE reservations
                SET status = 'Completed'
                WHERE book_id = ? AND student_id = ? AND status = 'Approved'
            """, (book_id, student_id))
            conn.execute("""
                INSERT INTO notifications(user_id,message,is_read)
                SELECT user_id, ?, 0 FROM students WHERE id=? AND user_id IS NOT NULL
            """, (f"Book issued successfully. Due date: {due_date}.", student_id))
            _log_activity(conn, "Book Issued", f"Book ID {book_id} issued to student ID {student_id}.", session.get("user_id"))
            conn.commit()
            conn.close()

            return redirect(url_for("issued_books"))

    books = conn.execute("""
        SELECT *
        FROM books
        WHERE quantity > 0
        ORDER BY title
    """).fetchall()

    students = conn.execute("""
        SELECT
            students.id,
            students.roll_no,
            students.course,
            students.department,
            students.semester,
            students.academic_year,
            users.full_name
        FROM students
        JOIN users ON users.id = students.user_id
        ORDER BY users.full_name
    """).fetchall()

    approved_reservations = conn.execute("""
        SELECT
            reservations.id,
            reservations.book_id,
            reservations.student_id,
            books.title,
            books.author,
            users.full_name,
            students.roll_no,
            reservations.reservation_date
        FROM reservations
        JOIN books ON books.id = reservations.book_id
        JOIN students ON students.id = reservations.student_id
        JOIN users ON users.id = students.user_id
        WHERE reservations.status = 'Approved'
        ORDER BY reservations.id ASC
    """).fetchall()

    conn.close()

    return render_template(
        "issue_book.html",
        books=books,
        students=students,
        approved_reservations=approved_reservations,
        error=error
    )


# =========================
# ISSUED BOOKS
# =========================

@app.route("/librarian/issues")
def issued_books():

    if "user_id" not in session or session["role"] != "librarian":
        return redirect(url_for("login"))

    conn = get_connection()

    issues = conn.execute("""
        SELECT
            issues.id,
            books.title,
            books.author,
            users.full_name,
            students.roll_no,
            issues.issue_date,
            issues.due_date,
            issues.return_date,
            issues.status,
            issues.fine
        FROM issues
        JOIN books ON books.id = issues.book_id
        JOIN students ON students.id = issues.student_id
        JOIN users ON users.id = students.user_id
        ORDER BY issues.id DESC
    """).fetchall()

    conn.close()

    # Calculate current live fine for overdue books
    today = date.today()

    updated_issues = []

    for issue in issues:
        try:
            if issue["status"] == "Issued" and issue["due_date"]:
                due = date.fromisoformat(issue["due_date"])
                late_days = (today - due).days

                if late_days > 0:
                    current_fine = late_days * 5
                else:
                    current_fine = 0
            else:
                current_fine = issue["fine"] or 0

            # sqlite3.Row cannot be modified directly, so create a normal dictionary
            item = dict(issue)
            item["fine"] = current_fine
            updated_issues.append(item)

        except Exception:
            item = dict(issue)
            item["fine"] = item.get("fine") or 0
            updated_issues.append(item)

    return render_template("issued_books.html", issues=updated_issues)


# =========================
# RETURN BOOK
# =========================

@app.route("/librarian/return/<int:issue_id>", methods=["POST"])
def return_book(issue_id):

    if "user_id" not in session or session["role"] != "librarian":
        return redirect(url_for("login"))

    conn = get_connection()

    issue = conn.execute("""
        SELECT *
        FROM issues
        WHERE id = ?
    """, (issue_id,)).fetchone()

    if issue and issue["status"] == "Issued":

        today = date.today()
        today_string = today.isoformat()
        fine = 0

        if issue["due_date"]:
            due_date = date.fromisoformat(issue["due_date"])
            late_days = (today - due_date).days

            if late_days > 0:
                fine = late_days * 5

        conn.execute("""
            UPDATE issues
            SET return_date = ?,
                status = 'Returned',
                fine = ?
            WHERE id = ?
        """, (today_string, fine, issue_id))

        conn.execute("""
            UPDATE books SET quantity = quantity + 1 WHERE id = ?
        """, (issue["book_id"],))
        conn.execute("""
            INSERT INTO notifications(user_id,message,is_read)
            SELECT user_id, ?, 0 FROM students WHERE id=? AND user_id IS NOT NULL
        """, (f"Book returned successfully. Fine recorded: ₹{fine}.", issue["student_id"]))
        _log_activity(conn, "Book Returned", f"Issue ID {issue_id} returned with fine ₹{fine}.", session.get("user_id"))
        conn.commit()

    conn.close()

    return redirect(url_for("issued_books"))



# =========================
# ADMIN REPORTS
# =========================

# =========================
# ADMIN REPORTS
# =========================

@app.route("/admin/reports")
def library_reports():

    if "user_id" not in session or session["role"] != "admin":
        return redirect(url_for("login"))

    return render_template("reports_menu.html")

@app.route("/admin/analytics")
def library_analytics():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn = get_connection()
    stats = {
        "books": conn.execute("SELECT COUNT(*) FROM books").fetchone()[0],
        "students": conn.execute("SELECT COUNT(*) FROM students").fetchone()[0],
        "librarians": conn.execute("SELECT COUNT(*) FROM librarians").fetchone()[0],
        "issued": conn.execute("SELECT COUNT(*) FROM issues WHERE status='Issued'").fetchone()[0],
        "returned": conn.execute("SELECT COUNT(*) FROM issues WHERE status='Returned'").fetchone()[0],
        "overdue": conn.execute("SELECT COUNT(*) FROM issues WHERE status='Issued' AND due_date IS NOT NULL AND date(due_date)<date('now')").fetchone()[0],
        "ebooks": conn.execute("SELECT COUNT(*) FROM ebooks").fetchone()[0],
        "journals": conn.execute("SELECT COUNT(*) FROM journals").fetchone()[0],
        "magazines": conn.execute("SELECT COUNT(*) FROM magazines").fetchone()[0],
        "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
    }
    popular = conn.execute("""
        SELECT b.title, b.author, COUNT(i.id) AS times_issued
        FROM books b LEFT JOIN issues i ON i.book_id=b.id
        GROUP BY b.id ORDER BY times_issued DESC, b.title LIMIT 10
    """).fetchall()
    monthly = conn.execute("""
        SELECT substr(issue_date,1,7) AS month, COUNT(*) AS count
        FROM issues GROUP BY month ORDER BY month DESC LIMIT 12
    """).fetchall()
    conn.close()
    return render_template("analytics.html", stats=stats, popular=popular, monthly=monthly)


@app.route("/admin/book-search")
def advanced_book_search():
    if not _require_role("admin", "librarian"):
        return redirect(url_for("login"))
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    conn = get_connection()
    like = f"%{q}%"
    books = conn.execute("""
        SELECT * FROM books
        WHERE (?='' OR title LIKE ? OR author LIKE ? OR category LIKE ? OR isbn LIKE ?)
          AND (?='' OR category=?)
        ORDER BY title COLLATE NOCASE
    """, (q,like,like,like,like,category,category)).fetchall()
    categories = conn.execute("SELECT DISTINCT category FROM books WHERE category IS NOT NULL AND category!='' ORDER BY category COLLATE NOCASE").fetchall()
    conn.close()
    return render_template("book_search.html", books=books, categories=categories, q=q, category=category)


@app.route("/admin/departments", methods=["GET", "POST"])
def manage_departments():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        action = request.form.get("action", "add")
        conn = get_connection()
        try:
            if action == "delete":
                conn.execute("DELETE FROM departments WHERE id=?", (int(request.form.get("id", 0)),))
            else:
                name = request.form.get("name", "").strip()
                code = request.form.get("code", "").strip().upper() or None
                if not name:
                    error = "Department name is required."
                else:
                    conn.execute("INSERT INTO departments(name,code) VALUES(?,?)", (name,code))
            if not error:
                conn.commit()
        except Exception:
            conn.rollback()
            error = "Department name or code already exists."
        conn.close()
    conn = get_connection()
    departments = conn.execute("SELECT * FROM departments ORDER BY name COLLATE NOCASE").fetchall()
    conn.close()
    return render_template("master_data.html", title="Department Management", item_label="Department", items=departments, error=error, mode="department")


@app.route("/admin/departments/delete/<int:item_id>", methods=["POST"])
def delete_department(item_id):
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn=get_connection(); conn.execute("DELETE FROM departments WHERE id=?",(item_id,)); conn.commit(); conn.close()
    return redirect(url_for("manage_departments"))


@app.route("/admin/book-categories", methods=["GET", "POST"])
def manage_book_categories():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        action=request.form.get("action","add")
        conn=get_connection()
        try:
            if action == "delete":
                conn.execute("DELETE FROM book_categories WHERE id=?",(int(request.form.get("id",0)),))
            else:
                name=request.form.get("name","").strip(); description=request.form.get("description","").strip()
                if not name: error="Category name is required."
                else: conn.execute("INSERT INTO book_categories(name,description) VALUES(?,?)",(name,description))
            if not error: conn.commit()
        except Exception:
            conn.rollback(); error="Category already exists."
        conn.close()
    conn=get_connection(); items=conn.execute("SELECT * FROM book_categories ORDER BY name COLLATE NOCASE").fetchall(); conn.close()
    return render_template("master_data.html", title="Book Categories", item_label="Book Category", items=items, error=error, mode="category")


@app.route("/admin/book-categories/delete/<int:item_id>", methods=["POST"])
def delete_book_category(item_id):
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn=get_connection(); conn.execute("DELETE FROM book_categories WHERE id=?",(item_id,)); conn.commit(); conn.close()
    return redirect(url_for("manage_book_categories"))


@app.route("/admin/librarian-activity")
def librarian_activity():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn=get_connection()
    rows=conn.execute("""
        SELECT la.*, COALESCE(u.full_name,'Unknown') AS librarian_name
        FROM librarian_activity la LEFT JOIN librarians l ON l.id=la.librarian_id
        LEFT JOIN users u ON u.id=l.user_id
        ORDER BY la.id DESC LIMIT 250
    """).fetchall()
    conn.close()
    return render_template("librarian_activity.html", rows=rows)


@app.route("/student/history")
def student_library_history():
    if not _require_role("student"):
        return redirect(url_for("login"))
    conn=get_connection()
    rows=conn.execute("""
        SELECT i.*, b.title, b.author, b.category
        FROM issues i JOIN books b ON b.id=i.book_id
        JOIN students s ON s.id=i.student_id
        WHERE s.user_id=? ORDER BY i.id DESC
    """,(session["user_id"],)).fetchall()
    conn.close()
    data=[]
    for row in rows:
        d=dict(row); d["live_fine"]=_current_fine(d.get("due_date"),d.get("status"),d.get("fine")); data.append(d)
    return render_template("history.html", rows=data)


@app.route("/student/card")
def student_library_card():
    if not _require_role("student"):
        return redirect(url_for("login"))
    conn=get_connection()
    student=conn.execute("""
        SELECT u.full_name,u.username,u.email,u.phone,s.*
        FROM users u JOIN students s ON s.user_id=u.id WHERE u.id=?
    """,(session["user_id"],)).fetchone()
    conn.close()
    if not student: return redirect(url_for("student_dashboard"))
    return render_template("student_card.html", student=student)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({
            "success": False,
            "message": "Username and password are required"
        }), 400

    conn = get_connection()
    user = conn.execute(
        "SELECT id, username, password, full_name, role, profile_image, phone, email "
        "FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user:
        conn.close()
        return jsonify({
            "success": False,
            "message": "Invalid username or password"
        }), 401

    if not check_password_hash(user["password"], password):
        conn.close()
        return jsonify({
            "success": False,
            "message": "Invalid username or password"
        }), 401

    result = {
        "id": user["id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "role": user["role"],
        "profile_image": user["profile_image"],
        "phone": user["phone"],
        "email": user["email"]
    }

    if user["role"] == "student":
        student = conn.execute("""
            SELECT id, roll_no, course, semester, academic_year,
                   profile_image, department
            FROM students
            WHERE user_id = ?
        """, (user["id"],)).fetchone()

        if student:
            result["student"] = dict(student)

    conn.close()

    return jsonify({
        "success": True,
        "user": result
    })


@app.route("/api/student/events", methods=["GET"])
def api_student_events():
    conn = get_connection()

    events = conn.execute("""
        SELECT id, title, description, event_date, event_time,
               venue, image_filename, video_filename
        FROM events
        ORDER BY event_date DESC, id DESC
    """).fetchall()

    conn.close()

    return jsonify({
        "success": True,
        "events": [dict(event) for event in events]
    })


@app.route("/api/student/books", methods=["GET"])
def api_student_books():
    conn = get_connection()

    books = conn.execute("""
        SELECT id, title, author, category, isbn, quantity, image
        FROM books
        ORDER BY title COLLATE NOCASE
    """).fetchall()

    conn.close()

    return jsonify({
        "success": True,
        "books": [dict(book) for book in books]
    })


@app.route("/api/student/notices", methods=["GET"])
def api_student_notices():
    conn = get_connection()

    notices = conn.execute("""
        SELECT id, title, description, notice_type, created_at
        FROM notices
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return jsonify({
        "success": True,
        "notices": [dict(notice) for notice in notices]
    })


@app.route("/api/student/profile/<int:user_id>", methods=["GET"])
def api_student_profile(user_id):
    if not _require_role("student", "admin", "librarian"):
        return jsonify({"success": False, "message": "Authentication required"}), 401
    if session.get("role") == "student" and session.get("user_id") != user_id:
        return jsonify({"success": False, "message": "Access denied"}), 403
    conn = get_connection()

    user = conn.execute("""
        SELECT id, username, full_name, role, profile_image, phone, email
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        conn.close()
        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404

    student = conn.execute("""
        SELECT id, roll_no, course, semester, academic_year,
               profile_image, department
        FROM students
        WHERE user_id = ?
    """, (user_id,)).fetchone()

    conn.close()

    return jsonify({
        "success": True,
        "user": dict(user),
        "student": dict(student) if student else None
    })


@app.route("/api/student/my-books/<int:user_id>", methods=["GET"])
def api_student_my_books(user_id):
    if not _require_role("student", "admin", "librarian"):
        return jsonify({"success": False, "message": "Authentication required"}), 401
    if session.get("role") == "student" and session.get("user_id") != user_id:
        return jsonify({"success": False, "message": "Access denied"}), 403
    conn = get_connection()

    student = conn.execute("""
        SELECT id
        FROM students
        WHERE user_id = ?
    """, (user_id,)).fetchone()

    if not student:
        conn.close()
        return jsonify({
            "success": False,
            "message": "Student not found"
        }), 404

    rows = conn.execute("""
        SELECT
            issues.id,
            issues.issue_date,
            issues.return_date,
            issues.status,
            issues.due_date,
            issues.fine,
            books.id AS book_id,
            books.title,
            books.author,
            books.category,
            books.isbn
        FROM issues
        JOIN books ON books.id = issues.book_id
        WHERE issues.student_id = ?
        ORDER BY issues.id DESC
    """, (student["id"],)).fetchall()

    conn.close()

    return jsonify({
        "success": True,
        "books": [dict(row) for row in rows]
    })


@app.route("/api/student/dashboard/<int:user_id>", methods=["GET"])
def api_student_dashboard(user_id):
    if not _require_role("student", "admin", "librarian"):
        return jsonify({"success": False, "message": "Authentication required"}), 401
    if session.get("role") == "student" and session.get("user_id") != user_id:
        return jsonify({"success": False, "message": "Access denied"}), 403
    conn = get_connection()

    user = conn.execute("""
        SELECT id, username, full_name, role, profile_image
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user or user["role"] != "student":
        conn.close()
        return jsonify({
            "success": False,
            "message": "Student not found"
        }), 404

    student = conn.execute("""
        SELECT id, roll_no, course, semester, academic_year, department
        FROM students
        WHERE user_id = ?
    """, (user_id,)).fetchone()

    books_count = conn.execute(
        "SELECT COUNT(*) FROM books"
    ).fetchone()[0]

    issued_count = 0
    if student:
        issued_count = conn.execute("""
            SELECT COUNT(*)
            FROM issues
            WHERE student_id = ? AND status = 'Issued'
        """, (student["id"],)).fetchone()[0]

    events_count = conn.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    notices_count = conn.execute(
        "SELECT COUNT(*) FROM notices"
    ).fetchone()[0]

    conn.close()

    return jsonify({
        "success": True,
        "user": dict(user),
        "student": dict(student) if student else None,
        "statistics": {
            "total_books": books_count,
            "my_issued_books": issued_count,
            "events": events_count,
            "notices": notices_count
        }
    })



@app.route("/student/reserve/<int:book_id>", methods=["POST"])
def student_reserve_book(book_id):
    if "user_id" not in session or session.get("role") != "student":
        return redirect(url_for("login"))
    conn=get_connection()
    student=conn.execute("SELECT id FROM students WHERE user_id=?",(session["user_id"],)).fetchone()
    book=conn.execute("SELECT id,quantity FROM books WHERE id=?",(book_id,)).fetchone()
    if not student or not book:
        conn.close(); return redirect(url_for("student_books"))
    existing=conn.execute("""SELECT id FROM reservations WHERE book_id=? AND student_id=? AND status IN ('Pending','Approved')""",
                          (book_id,student["id"])).fetchone()
    if existing:
        pass
    elif book["quantity"] > 0:
        conn.execute("INSERT INTO notifications(user_id,message,is_read) VALUES(?,?,0)",
                     (session["user_id"],"This book is currently available, so a reservation is not required."))
        conn.commit()
    else:
        conn.execute("INSERT INTO reservations(book_id,student_id,reservation_date,status) VALUES(?,?,date('now'),'Pending')",
                     (book_id,student["id"]))
        conn.execute("INSERT INTO notifications(user_id,message,is_read) VALUES(?,?,0)",
                     (session["user_id"],"Your reservation request was created."))
        conn.commit()
    conn.close()
    return redirect(url_for("student_books"))

@app.route("/student/my-books")
def student_my_books():
    if "user_id" not in session or session.get("role") != "student": return redirect(url_for("login"))
    conn=get_connection()
    rows=conn.execute("""SELECT i.*,b.title,b.author,b.category FROM issues i JOIN books b ON b.id=i.book_id JOIN students s ON s.id=i.student_id WHERE s.user_id=? ORDER BY i.id DESC""",(session["user_id"],)).fetchall()
    conn.close()
    return render_template("student_my_books_modern.html", rows=rows)

@app.route("/student/reservations")
def student_reservations():
    if "user_id" not in session or session.get("role") != "student": return redirect(url_for("login"))
    conn=get_connection()
    rows=conn.execute("""SELECT r.*,b.title,b.author FROM reservations r JOIN books b ON b.id=r.book_id JOIN students s ON s.id=r.student_id WHERE s.user_id=? ORDER BY r.id DESC""",(session["user_id"],)).fetchall()
    conn.close()
    return render_template("student_reservations_modern.html", rows=rows)

@app.route("/student/notifications")
def student_notifications():
    if "user_id" not in session or session.get("role") != "student": return redirect(url_for("login"))
    conn=get_connection()
    rows=conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC",(session["user_id"],)).fetchall()
    conn.close()
    return render_template("student_notifications_modern.html", rows=rows)

@app.route("/student/events")
def student_events_page():
    if not _require_role("student"): return redirect(url_for("login"))
    conn=get_connection(); rows=conn.execute("SELECT * FROM events ORDER BY event_date DESC,id DESC").fetchall(); conn.close()
    return render_template("student_events_modern.html", events=rows)

@app.route("/student/notices")
def student_notices_page():
    if not _require_role("student"): return redirect(url_for("login"))
    conn=get_connection(); rows=conn.execute("SELECT * FROM notices ORDER BY id DESC").fetchall(); conn.close()
    return render_template("student_notices_modern.html", notices=rows)

# ============================================================
# DIGITAL LIBRARY: E-BOOKS, JOURNALS AND UNIFIED SEARCH
# ============================================================

DIGITAL_UPLOAD_ROOT = os.path.join(app.root_path, "static", "uploads", "digital")
EBOOK_FOLDER = os.path.join(DIGITAL_UPLOAD_ROOT, "ebooks")
JOURNAL_FOLDER = os.path.join(DIGITAL_UPLOAD_ROOT, "journals")
MAGAZINE_FOLDER = os.path.join(DIGITAL_UPLOAD_ROOT, "magazines")
for _folder in (EBOOK_FOLDER, JOURNAL_FOLDER, MAGAZINE_FOLDER):
    os.makedirs(_folder, exist_ok=True)

ALLOWED_PDF_EXT = {".pdf"}
ALLOWED_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp"}

def _save_digital_file(file_obj, folder, prefix, allowed=None):
    if not file_obj or not file_obj.filename:
        return None
    original = secure_filename(file_obj.filename)
    ext = os.path.splitext(original)[1].lower()
    allowed = allowed or (ALLOWED_PDF_EXT | ALLOWED_IMAGE_EXT)
    if ext not in allowed:
        return None
    import uuid
    filename = f"{prefix}_{uuid.uuid4().hex}{ext}"
    os.makedirs(folder, exist_ok=True)
    file_obj.save(os.path.join(folder, filename))
    return filename

def _digital_auth(admin=False):
    if "user_id" not in session:
        return False
    if admin:
        return session.get("role") in ("admin", "librarian")
    return True

@app.route("/digital-library")
def digital_library():
    if not _digital_auth():
        return redirect(url_for("login"))
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    conn = get_connection()
    like = f"%{q}%"
    ebooks = conn.execute("""
        SELECT * FROM ebooks
        WHERE (? = '' OR title LIKE ? OR author LIKE ? OR category LIKE ? OR publisher LIKE ?)
          AND (? = '' OR category = ?)
        ORDER BY id DESC
    """, (q, like, like, like, like, category, category)).fetchall()
    journals = conn.execute("""
        SELECT * FROM journals
        WHERE (? = '' OR title LIKE ? OR publisher LIKE ? OR category LIKE ?)
          AND (? = '' OR category = ?)
        ORDER BY id DESC
    """, (q, like, like, like, category, category)).fetchall()
    magazines = conn.execute("SELECT * FROM magazines ORDER BY id DESC").fetchall()
    cats = conn.execute("""
        SELECT category FROM ebooks WHERE category IS NOT NULL AND category != ''
        UNION SELECT category FROM journals WHERE category IS NOT NULL AND category != ''
        ORDER BY category
    """).fetchall()
    stats = {
        "ebooks": conn.execute("SELECT COUNT(*) FROM ebooks").fetchone()[0],
        "journals": conn.execute("SELECT COUNT(*) FROM journals").fetchone()[0],
        "magazines": conn.execute("SELECT COUNT(*) FROM magazines").fetchone()[0],
        "books": conn.execute("SELECT COUNT(*) FROM books").fetchone()[0],
    }
    conn.close()
    return render_template("digital_library.html", ebooks=ebooks, journals=journals,
                           magazines=magazines, categories=cats, stats=stats, q=q, category=category)

@app.route("/admin/ebooks")
def manage_ebooks():
    if not _digital_auth(admin=True):
        return redirect(url_for("login"))
    conn = get_connection()
    ebooks = conn.execute("SELECT * FROM ebooks ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("manage_ebooks.html", ebooks=ebooks)

@app.route("/admin/ebooks/add", methods=["GET", "POST"])
def add_ebook():
    if not _digital_auth(admin=True):
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        pdf = request.files.get("pdf_file")
        if not title or not pdf or not pdf.filename:
            error = "Title and PDF are required."
        else:
            pdf_name = _save_digital_file(pdf, EBOOK_FOLDER, "ebook", ALLOWED_PDF_EXT)
            if not pdf_name or not pdf_name.lower().endswith(".pdf"):
                error = "Please upload a valid PDF file."
            else:
                cover = request.files.get("cover_image")
                cover_name = _save_digital_file(cover, EBOOK_FOLDER, "ebook_cover", ALLOWED_IMAGE_EXT) if cover and cover.filename else None
                conn = get_connection()
                conn.execute("""
                    INSERT INTO ebooks
                    (title, author, category, isbn, publisher, publication_year, description,
                     cover_image, pdf_file, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (title, request.form.get("author","").strip(), request.form.get("category","").strip(),
                      request.form.get("isbn","").strip(), request.form.get("publisher","").strip(),
                      request.form.get("publication_year","").strip(), request.form.get("description","").strip(),
                      cover_name, pdf_name, session["user_id"]))
                conn.commit(); conn.close()
                return redirect(url_for("manage_ebooks"))
    return render_template("add_ebook.html", error=error)

@app.route("/admin/ebooks/delete/<int:ebook_id>", methods=["POST"])
def delete_ebook(ebook_id):
    if not _digital_auth(admin=True):
        return redirect(url_for("login"))
    conn = get_connection()
    row = conn.execute("SELECT pdf_file, cover_image FROM ebooks WHERE id=?", (ebook_id,)).fetchone()
    conn.execute("DELETE FROM ebooks WHERE id=?", (ebook_id,))
    conn.commit(); conn.close()
    if row:
        for name in (row["pdf_file"], row["cover_image"]):
            if name:
                try: os.remove(os.path.join(EBOOK_FOLDER, name))
                except OSError: pass
    return redirect(url_for("manage_ebooks"))

@app.route("/ebooks/<int:ebook_id>/read")
def read_ebook(ebook_id):
    if not _digital_auth():
        return redirect(url_for("login"))
    conn = get_connection()
    row = conn.execute("SELECT * FROM ebooks WHERE id=?", (ebook_id,)).fetchone()
    if not row:
        conn.close(); return "E-Book not found", 404
    pdf_path=os.path.join(EBOOK_FOLDER,row["pdf_file"])
    if not os.path.exists(pdf_path):
        conn.close(); return "The e-book PDF file is missing from the server.",404
    if session.get("role") == "student":
        conn.execute("""
            INSERT INTO digital_read_history(user_id, resource_type, resource_id, last_opened)
            VALUES (?, 'ebook', ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id, resource_type, resource_id)
            DO UPDATE SET last_opened=CURRENT_TIMESTAMP
        """, (session["user_id"], ebook_id))
        conn.commit()
    conn.close()
    return render_template("digital_reader.html", resource=row, resource_type="E-Book",
                           file_url=url_for("static", filename="uploads/digital/ebooks/"+row["pdf_file"]))

@app.route("/admin/journals")
def manage_journals():
    if not _digital_auth(admin=True):
        return redirect(url_for("login"))
    conn = get_connection()
    journals = conn.execute("SELECT * FROM journals ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("manage_journals.html", journals=journals)

@app.route("/admin/journals/add", methods=["GET", "POST"])
def add_journal():
    if not _digital_auth(admin=True):
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        title = request.form.get("title","").strip()
        if not title:
            error = "Journal title is required."
        else:
            pdf = request.files.get("pdf_file")
            pdf_name = _save_digital_file(pdf, JOURNAL_FOLDER, "journal", ALLOWED_PDF_EXT) if pdf and pdf.filename else None
            cover = request.files.get("cover_image")
            cover_name = _save_digital_file(cover, JOURNAL_FOLDER, "journal_cover", ALLOWED_IMAGE_EXT) if cover and cover.filename else None
            conn = get_connection()
            conn.execute("""
                INSERT INTO journals
                (title,publisher,category,volume,issue,publication_year,description,cover_image,pdf_file,uploaded_by)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (title, request.form.get("publisher","").strip(), request.form.get("category","").strip(),
                  request.form.get("volume","").strip(), request.form.get("issue","").strip(),
                  request.form.get("publication_year","").strip(), request.form.get("description","").strip(),
                  cover_name, pdf_name, session["user_id"]))
            conn.commit(); conn.close()
            return redirect(url_for("manage_journals"))
    return render_template("add_journal.html", error=error)

@app.route("/admin/journals/delete/<int:journal_id>", methods=["POST"])
def delete_journal(journal_id):
    if not _digital_auth(admin=True):
        return redirect(url_for("login"))
    conn=get_connection()
    row=conn.execute("SELECT pdf_file,cover_image FROM journals WHERE id=?", (journal_id,)).fetchone()
    conn.execute("DELETE FROM journals WHERE id=?", (journal_id,))
    conn.commit(); conn.close()
    if row:
        for name in (row["pdf_file"],row["cover_image"]):
            if name:
                try: os.remove(os.path.join(JOURNAL_FOLDER,name))
                except OSError: pass
    return redirect(url_for("manage_journals"))

@app.route("/journals/<int:journal_id>/read")
def read_journal(journal_id):
    if not _digital_auth():
        return redirect(url_for("login"))
    conn=get_connection()
    row=conn.execute("SELECT * FROM journals WHERE id=?",(journal_id,)).fetchone()
    if not row:
        conn.close(); return "Journal not found",404
    if not row["pdf_file"]:
        conn.close(); return "No PDF is available for this journal.",404
    pdf_path=os.path.join(JOURNAL_FOLDER,row["pdf_file"])
    if not os.path.exists(pdf_path):
        conn.close(); return "The journal PDF file is missing from the server.",404
    if session.get("role") == "student":
        conn.execute("""INSERT INTO digital_read_history(user_id,resource_type,resource_id,last_opened) VALUES (?, 'journal', ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(user_id,resource_type,resource_id) DO UPDATE SET last_opened=CURRENT_TIMESTAMP""",(session["user_id"],journal_id))
        conn.commit()
    conn.close()
    return render_template("digital_reader.html", resource=row, resource_type="Journal",
                           file_url=url_for("static", filename="uploads/digital/journals/"+row["pdf_file"]))

@app.route("/magazines/<int:magazine_id>/read")
def read_magazine(magazine_id):
    if not _digital_auth():
        return redirect(url_for("login"))
    conn=get_connection()
    row=conn.execute("SELECT * FROM magazines WHERE id=?",(magazine_id,)).fetchone()
    if not row:
        conn.close(); return "Magazine not found",404
    if not row["pdf_file"]:
        conn.close(); return "No PDF is available for this magazine.",404
    pdf_path=os.path.join(app.root_path,"static","uploads","magazines","pdfs",row["pdf_file"])
    if not os.path.exists(pdf_path):
        conn.close(); return "The magazine PDF file is missing from the server.",404
    if session.get("role") == "student":
        conn.execute("""
            INSERT INTO digital_read_history(user_id,resource_type,resource_id,last_opened)
            VALUES (?, 'magazine', ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id,resource_type,resource_id) DO UPDATE SET last_opened=CURRENT_TIMESTAMP
        """,(session["user_id"],magazine_id)); conn.commit()
    conn.close()
    return render_template("digital_reader.html", resource=row, resource_type="Magazine",
                           file_url=url_for("static", filename="uploads/magazines/pdfs/"+row["pdf_file"]))

@app.route("/digital/<resource_type>/<int:resource_id>/bookmark", methods=["POST"])
def digital_bookmark(resource_type, resource_id):
    if not _digital_auth():
        return redirect(url_for("login"))
    if resource_type not in ("ebook","journal","magazine"):
        return "Invalid resource",400
    table = {"ebook":"ebooks", "journal":"journals", "magazine":"magazines"}[resource_type]
    conn=get_connection()
    if not conn.execute(f"SELECT 1 FROM {table} WHERE id=?",(resource_id,)).fetchone():
        conn.close(); return "Resource not found",404
    existing=conn.execute("""SELECT id FROM digital_bookmarks WHERE user_id=? AND resource_type=? AND resource_id=?""",
                          (session["user_id"],resource_type,resource_id)).fetchone()
    if existing:
        conn.execute("DELETE FROM digital_bookmarks WHERE id=?",(existing["id"],))
    else:
        conn.execute("""INSERT OR IGNORE INTO digital_bookmarks(user_id,resource_type,resource_id) VALUES (?,?,?)""",
                     (session["user_id"],resource_type,resource_id))
    conn.commit(); conn.close()
    return redirect(request.referrer or url_for("digital_library"))

@app.route("/student/bookmarks")
def student_bookmarks():
    if not _require_role("student"):
        return redirect(url_for("login"))
    conn=get_connection()
    rows=conn.execute("""
        SELECT db.resource_type,db.resource_id,db.created_at,
               CASE db.resource_type WHEN 'ebook' THEN e.title WHEN 'journal' THEN j.title WHEN 'magazine' THEN m.title END AS title,
               CASE db.resource_type WHEN 'ebook' THEN e.author WHEN 'journal' THEN j.publisher WHEN 'magazine' THEN m.department END AS author,
               CASE db.resource_type WHEN 'ebook' THEN e.cover_image WHEN 'journal' THEN j.cover_image WHEN 'magazine' THEN m.cover_image END AS cover_image,
               CASE db.resource_type WHEN 'ebook' THEN e.pdf_file WHEN 'journal' THEN j.pdf_file WHEN 'magazine' THEN m.pdf_file END AS pdf_file
        FROM digital_bookmarks db
        LEFT JOIN ebooks e ON db.resource_type='ebook' AND e.id=db.resource_id
        LEFT JOIN journals j ON db.resource_type='journal' AND j.id=db.resource_id
        LEFT JOIN magazines m ON db.resource_type='magazine' AND m.id=db.resource_id
        WHERE db.user_id=? ORDER BY db.id DESC
    """,(session["user_id"],)).fetchall()
    conn.close()
    return render_template("student_bookmarks.html", rows=rows)

@app.route("/student/digital-library")
def student_digital_library():
    return redirect(url_for("digital_library"))



# ============================================================
# UI / NAVIGATION COMPLETENESS ROUTES
# These routes keep every visible navigation item functional.
# ============================================================

def _require_role(*roles):
    return "user_id" in session and session.get("role") in roles

@app.route("/librarian/profile")
def librarian_profile():
    if not _require_role("librarian"):
        return redirect(url_for("login"))
    conn=get_connection()
    librarian=conn.execute("""
        SELECT l.*,u.full_name,u.username,u.email,u.phone,u.profile_image
        FROM librarians l JOIN users u ON u.id=l.user_id WHERE l.user_id=?
    """,(session["user_id"],)).fetchone()
    conn.close()
    if not librarian: return redirect(url_for("librarian_dashboard"))
    return render_template("librarian_profile.html", librarian=librarian)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))
    error = None
    success = None
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        conn = get_connection()
        user = conn.execute("SELECT password FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user or not check_password_hash(user["password"], current):
            error = "Current password is incorrect."
        elif not _strong_password(new):
            error = "New password must contain at least 10 characters with letters and numbers."
        elif new != confirm:
            error = "New passwords do not match."
        else:
            conn.execute("UPDATE users SET password=?, must_change_password=0 WHERE id=?",
                         (generate_password_hash(new), session["user_id"]))
            conn.commit()
            success = "Password changed successfully."
            if session.get("role") == "student":
                contact_user = conn.execute("SELECT email, phone, email_verified, phone_verified FROM users WHERE id=?", (session["user_id"],)).fetchone()
                conn.close()
                if contact_user and ((contact_user["email"] and not contact_user["email_verified"]) or (contact_user["phone"] and not contact_user["phone_verified"])):
                    return redirect(url_for("verify_contact"))
                return redirect(url_for("home"))
        conn.close()
    return render_template("change_password.html", error=error, success=success)

@app.route("/admin/account")
def admin_account():
    return redirect(url_for("admin_profile"))

@app.route("/admin/profile", methods=["GET", "POST"])
def admin_profile():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn = get_connection()
    error = None
    success = None
    if request.method == "POST":
        action = request.form.get("action", "edit_details")
        if action == "photo":
            f = request.files.get("profile_image")
            if f and f.filename:
                folder = os.path.join(app.root_path, "static", "uploads", "admins")
                os.makedirs(folder, exist_ok=True)
                name = secure_filename(f.filename)
                ext = os.path.splitext(name)[1].lower()
                if ext in {".jpg",".jpeg",".png",".webp"}:
                    import uuid
                    final = f"admin_{session['user_id']}_{uuid.uuid4().hex}{ext}"
                    f.save(os.path.join(folder, final))
                    conn.execute("UPDATE users SET profile_image=? WHERE id=?", (final, session["user_id"]))
                    conn.commit()
                    success = "Profile photo updated."
                else:
                    error = "Use JPG, PNG or WEBP for profile photos."
        else:
            full_name = request.form.get("full_name","").strip()
            username = request.form.get("username","").strip()
            email = request.form.get("email","").strip()
            phone = request.form.get("phone","").strip()
            if not full_name or not username:
                error = "Full name and username are required."
            else:
                exists = conn.execute("SELECT id FROM users WHERE username=? AND id<>?",
                                      (username, session["user_id"])).fetchone()
                if exists:
                    error = "That username is already in use."
                else:
                    conn.execute("""UPDATE users SET full_name=?, username=?, email=?, phone=? WHERE id=?""",
                                 (full_name, username, email, phone, session["user_id"]))
                    conn.commit()
                    session["full_name"] = full_name
                    session["username"] = username
                    success = "Profile updated successfully."
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()
    return render_template("admin_profile.html", user=user, error=error, success=success)

@app.route("/admin/manage-admins", methods=["GET", "POST"])
def manage_admins():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    error = None
    success = None
    conn = get_connection()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            full_name = request.form.get("full_name","").strip()
            username = request.form.get("username","").strip()
            password = request.form.get("password","")
            if not full_name or not username or not _strong_password(password):
                error = "Name, username and a password of at least 10 characters with letters and numbers are required."
            elif conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                error = "Username already exists."
            else:
                conn.execute("""INSERT INTO users(username,password,full_name,role) VALUES(?,?,?,'admin')""",
                             (username, generate_password_hash(password), full_name))
                conn.commit()
                success = "Administrator added successfully."
        elif action == "remove":
            try:
                aid = int(request.form.get("admin_id"))
            except Exception:
                aid = 0
            if aid == session.get("user_id"):
                error = "You cannot remove the currently logged-in administrator."
            else:
                target = conn.execute("SELECT profile_image FROM users WHERE id=? AND role='admin'", (aid,)).fetchone()
                if not target:
                    error = "Administrator not found."
                else:
                    # Preserve historical records by clearing ownership before removing the account.
                    for table in ("ebooks","journals","magazines","events","notices"):
                        conn.execute(f"UPDATE {table} SET uploaded_by=NULL WHERE uploaded_by=?", (aid,)) if table in ("ebooks","journals","magazines") else conn.execute(f"UPDATE {table} SET created_by=NULL WHERE created_by=?", (aid,))
                    conn.execute("DELETE FROM users WHERE id=? AND role='admin'", (aid,))
                    conn.commit()
                    success = "Administrator removed."
    admins = conn.execute("SELECT id,full_name,username,email,phone FROM users WHERE role='admin' ORDER BY id").fetchall()
    conn.close()
    return render_template("manage_admins.html", admins=admins, error=error, success=success)

@app.route("/admin/notices", methods=["GET", "POST"])
def admin_notices():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn = get_connection()
    success = None
    error = None
    if request.method == "POST":
        action = request.form.get("action","create")
        if action == "delete":
            try: nid = int(request.form.get("notice_id"))
            except Exception: nid = 0
            conn.execute("DELETE FROM notices WHERE id=?", (nid,))
            conn.commit()
            success = "Notice deleted."
        else:
            title = request.form.get("title","").strip()
            desc = request.form.get("description","").strip()
            typ = request.form.get("notice_type","General").strip() or "General"
            if not title or not desc:
                error = "Notice title and description are required."
            else:
                conn.execute("""INSERT INTO notices(title,description,notice_type,created_by) VALUES(?,?,?,?)""",
                             (title,desc,typ,session["user_id"]))
                _notify_students(conn, f"New notice: {title}")
                conn.commit()
                success = "Notice published and students notified."
    notices = conn.execute("""SELECT n.*, u.full_name AS created_by_name
                              FROM notices n LEFT JOIN users u ON u.id=n.created_by
                              ORDER BY n.id DESC""").fetchall()
    conn.close()
    return render_template("admin_notices.html", notices=notices, success=success, error=error)

@app.route("/admin/events", methods=["GET", "POST"])
def admin_events():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn = get_connection()
    success = None
    error = None
    folder = os.path.join(app.root_path, "static", "uploads", "events")
    os.makedirs(folder, exist_ok=True)
    if request.method == "POST":
        action = request.form.get("action","add")
        if action == "delete":
            try: eid = int(request.form.get("event_id"))
            except Exception: eid = 0
            row = conn.execute("SELECT image_filename,video_filename FROM events WHERE id=?", (eid,)).fetchone()
            conn.execute("DELETE FROM events WHERE id=?", (eid,))
            conn.commit()
            if row:
                for key in ("image_filename","video_filename"):
                    if row[key]:
                        try: os.remove(os.path.join(folder,row[key]))
                        except OSError: pass
            success = "Event deleted."
        else:
            title = request.form.get("title","").strip()
            event_date = request.form.get("event_date","").strip()
            if not title or not event_date:
                error = "Event title and event date are required."
            else:
                import uuid
                image = request.files.get("event_image")
                video = request.files.get("event_video")
                image_name = video_name = None
                if image and image.filename:
                    ext = os.path.splitext(secure_filename(image.filename))[1].lower()
                    if ext in {".jpg",".jpeg",".png",".webp"}:
                        image_name = f"event_{uuid.uuid4().hex}{ext}"
                        image.save(os.path.join(folder,image_name))
                if video and video.filename:
                    ext = os.path.splitext(secure_filename(video.filename))[1].lower()
                    if ext in {".mp4",".webm",".mov",".m4v"}:
                        video_name = f"event_{uuid.uuid4().hex}{ext}"
                        video.save(os.path.join(folder,video_name))
                conn.execute("""INSERT INTO events(title,description,event_date,event_time,venue,image_filename,video_filename,created_by)
                                VALUES(?,?,?,?,?,?,?,?)""",
                             (title, request.form.get("description","").strip(),
                              event_date, request.form.get("event_time","").strip(),
                              request.form.get("venue","").strip(), image_name, video_name, session["user_id"]))
                _notify_students(conn, f"New library event: {title}")
                conn.commit()
                success = "Event published and students notified."
    events = conn.execute("SELECT * FROM events ORDER BY event_date DESC,id DESC").fetchall()
    conn.close()
    return render_template("admin_events.html", events=events, success=success, error=error)

@app.route("/events/<int:event_id>")
def event_detail(event_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn=get_connection(); event=conn.execute("SELECT * FROM events WHERE id=?",(event_id,)).fetchone(); conn.close()
    if not event: return "Event not found",404
    return render_template("event_detail.html",event=event)

@app.route("/librarian/events", methods=["GET", "POST"])
def librarian_events():
    if not _require_role("librarian"):
        return redirect(url_for("login"))

    conn = get_connection()
    success = None
    error = None
    folder = os.path.join(app.root_path, "static", "uploads", "events")
    os.makedirs(folder, exist_ok=True)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        event_date = request.form.get("event_date", "").strip()
        if not title or not event_date:
            error = "Event title and event date are required."
        else:
            import uuid
            image = request.files.get("event_image")
            video = request.files.get("event_video")
            image_name = video_name = None

            if image and image.filename:
                ext = os.path.splitext(secure_filename(image.filename))[1].lower()
                if ext in {".jpg", ".jpeg", ".png", ".webp"}:
                    image_name = f"event_{uuid.uuid4().hex}{ext}"
                    image.save(os.path.join(folder, image_name))

            if video and video.filename:
                ext = os.path.splitext(secure_filename(video.filename))[1].lower()
                if ext in {".mp4", ".webm", ".mov", ".m4v"}:
                    video_name = f"event_{uuid.uuid4().hex}{ext}"
                    video.save(os.path.join(folder, video_name))

            conn.execute("""INSERT INTO events(title,description,event_date,event_time,venue,image_filename,video_filename,created_by)
                            VALUES(?,?,?,?,?,?,?,?)""",
                         (title, request.form.get("description", "").strip(),
                          event_date, request.form.get("event_time", "").strip(),
                          request.form.get("venue", "").strip(), image_name, video_name, session["user_id"]))
            _notify_students(conn, f"New library event: {title}")
            conn.commit()
            success = "Event published and students notified."

    events = conn.execute("SELECT * FROM events ORDER BY event_date DESC,id DESC").fetchall()
    conn.close()
    return render_template("librarian_events.html", events=events, success=success, error=error)

@app.route("/admin/fines")
def admin_fines():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn=get_connection()
    rows=conn.execute("""SELECT i.*,b.title,users.full_name,students.roll_no
                        FROM issues i JOIN books b ON b.id=i.book_id
                        JOIN students ON students.id=i.student_id
                        JOIN users ON users.id=students.user_id
                        ORDER BY i.id DESC""").fetchall()
    conn.close()
    data=[]; total=0; overdue=0
    for r in rows:
        d=dict(r); d["fine"]=_current_fine(d.get("due_date"),d.get("status"),d.get("fine")); d["late_days"]=0
        if d.get("status")=="Issued" and d.get("due_date"):
            try: d["late_days"]=max(0,(date.today()-date.fromisoformat(d["due_date"])).days)
            except (TypeError,ValueError): pass
        if d["late_days"]>0: overdue+=1
        total += d["fine"] or 0
        data.append(d)
    return render_template("admin_fines.html", fines=data, total_fine=round(total,2), overdue_count=overdue)

@app.route("/librarian/fines")
def librarian_fines():
    if not _require_role("librarian"):
        return redirect(url_for("login"))
    return redirect(url_for("issued_books"))

@app.route("/admin/late-notifications")
def admin_late_notifications():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn=get_connection()
    rows=conn.execute("""SELECT i.*,b.title,users.full_name,students.roll_no
                         FROM issues i JOIN books b ON b.id=i.book_id
                         JOIN students ON students.id=i.student_id JOIN users ON users.id=students.user_id
                         WHERE i.status='Issued' AND i.due_date IS NOT NULL AND date(i.due_date)<date('now')
                         ORDER BY i.due_date""").fetchall()
    conn.close(); data=[]
    for r in rows:
        d=dict(r); d["late_days"]=_current_fine(d.get("due_date"),"Issued",0)//5; d["fine"]=_current_fine(d.get("due_date"),"Issued",0); data.append(d)
    return render_template("admin_late_notifications.html", late_books=data, rows=data)

@app.route("/librarian/late-notifications")
def librarian_late_notifications():
    if not _require_role("librarian"):
        return redirect(url_for("login"))
    conn=get_connection()
    rows=conn.execute("""SELECT i.*,b.title,users.full_name,students.roll_no
                         FROM issues i JOIN books b ON b.id=i.book_id
                         JOIN students ON students.id=i.student_id JOIN users ON users.id=students.user_id
                         WHERE i.status='Issued' AND i.due_date IS NOT NULL AND date(i.due_date)<date('now')
                         ORDER BY i.due_date""").fetchall()
    conn.close(); data=[]
    for r in rows:
        d=dict(r); d["late_days"]=_current_fine(d.get("due_date"),"Issued",0)//5; d["fine"]=_current_fine(d.get("due_date"),"Issued",0); data.append(d)
    return render_template("librarian_late_notifications.html", rows=data, late_books=data)

@app.route("/admin/reservations")
def admin_reservations():
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn=get_connection()
    rows=conn.execute("""SELECT r.*,b.title,b.author,s.roll_no,u.full_name
                         FROM reservations r JOIN books b ON b.id=r.book_id
                         JOIN students s ON s.id=r.student_id JOIN users u ON u.id=s.user_id
                         ORDER BY r.id DESC""").fetchall()
    conn.close()
    return render_template("admin_reservations.html", reservations=rows)

@app.route("/librarian/reservations")
def librarian_reservations():
    if not _require_role("librarian"):
        return redirect(url_for("login"))
    conn=get_connection()
    rows=conn.execute("""SELECT r.*,b.title,s.roll_no,u.full_name
                         FROM reservations r JOIN books b ON b.id=r.book_id
                         JOIN students s ON s.id=r.student_id JOIN users u ON u.id=s.user_id
                         ORDER BY r.id DESC""").fetchall()
    conn.close()
    return render_template("librarian_reservations.html", reservations=rows)

@app.route("/librarian/reservations/approve/<int:reservation_id>", methods=["POST"])
def approve_reservation(reservation_id):
    if not _require_role("librarian"):
        return redirect(url_for("login"))
    conn=get_connection()
    row=conn.execute("""SELECT r.student_id,b.title,s.user_id FROM reservations r JOIN books b ON b.id=r.book_id JOIN students s ON s.id=r.student_id WHERE r.id=?""",(reservation_id,)).fetchone()
    conn.execute("UPDATE reservations SET status='Approved' WHERE id=?",(reservation_id,))
    if row:
        conn.execute("INSERT INTO notifications(user_id,message,is_read) VALUES(?,?,0)",(row["user_id"],f"Your reservation for {row['title']} was approved."))
    conn.commit(); conn.close()
    return redirect(url_for("librarian_reservations"))

@app.route("/librarian/reservations/reject/<int:reservation_id>", methods=["POST"])
def reject_reservation(reservation_id):
    if not _require_role("librarian"):
        return redirect(url_for("login"))
    conn=get_connection()
    row=conn.execute("""SELECT r.student_id,b.title,s.user_id FROM reservations r JOIN books b ON b.id=r.book_id JOIN students s ON s.id=r.student_id WHERE r.id=?""",(reservation_id,)).fetchone()
    conn.execute("UPDATE reservations SET status='Rejected' WHERE id=?",(reservation_id,))
    if row:
        conn.execute("INSERT INTO notifications(user_id,message,is_read) VALUES(?,?,0)",(row["user_id"],f"Your reservation for {row['title']} was rejected."))
    conn.commit(); conn.close()
    return redirect(url_for("librarian_reservations"))

@app.route("/student/reservations/cancel/<int:reservation_id>", methods=["POST"])
def cancel_reservation(reservation_id):
    if not _require_role("student"):
        return redirect(url_for("login"))
    conn=get_connection()
    conn.execute("""UPDATE reservations SET status='Cancelled'
                    WHERE id=? AND student_id=(SELECT id FROM students WHERE user_id=?)""",
                 (reservation_id,session["user_id"]))
    conn.commit(); conn.close()
    return redirect(url_for("student_reservations"))

@app.route("/student/profile/edit", methods=["GET","POST"])
def student_edit_profile():
    if not _require_role("student"):
        return redirect(url_for("login"))
    conn=get_connection()
    student=conn.execute("""SELECT u.id AS user_id,u.full_name,u.username,u.email,u.phone,
                                   s.id,s.roll_no,s.course,s.semester,s.academic_year,s.profile_image,s.department
                            FROM users u JOIN students s ON s.user_id=u.id WHERE u.id=?""",
                         (session["user_id"],)).fetchone()
    error=None
    if not student:
        conn.close()
        return redirect(url_for("student_dashboard"))
    if request.method=="POST":
        full_name=request.form.get("full_name","").strip()
        course=request.form.get("course","").strip()
        semester=request.form.get("semester","").strip()
        academic_year=request.form.get("academic_year","").strip()
        f=request.files.get("profile_image")
        img=student["profile_image"]
        if f and f.filename:
            ext=os.path.splitext(secure_filename(f.filename))[1].lower()
            if ext in {".jpg",".jpeg",".png",".webp"}:
                folder=os.path.join(app.root_path,"static","uploads","students")
                os.makedirs(folder,exist_ok=True)
                img=f"student_{student['id']}_{__import__('uuid').uuid4().hex}{ext}"
                f.save(os.path.join(folder,img))
        conn.execute("UPDATE users SET full_name=? WHERE id=?",(full_name,session["user_id"]))
        conn.execute("""UPDATE students SET course=?,semester=?,academic_year=?,profile_image=? WHERE id=?""",
                     (course,int(semester) if semester.isdigit() else None,academic_year,img,student["id"]))
        conn.commit()
        session["full_name"]=full_name
        conn.close()
        return redirect(url_for("student_profile"))
    conn.close()
    return render_template("student_edit_profile.html",student=student,error=error)

@app.route("/student/profile")
def student_profile():
    if not _require_role("student"):
        return redirect(url_for("login"))
    conn=get_connection()
    student=conn.execute("""SELECT u.*,s.roll_no,s.course,s.semester,s.academic_year,s.profile_image,s.department
                            FROM users u JOIN students s ON s.user_id=u.id WHERE u.id=?""",
                         (session["user_id"],)).fetchone()
    conn.close()
    return render_template("student_profile.html",student=student)

@app.route("/student/profile/view")
def repaired_student_profile():
    return redirect(url_for("student_profile"))

@app.route("/verify-contact", methods=["GET", "POST"])
def verify_contact():
    if "user_id" not in session or session.get("role") != "student":
        return redirect(url_for("login"))
    conn=get_connection(); user=conn.execute("SELECT id,email,phone,email_verified,phone_verified FROM users WHERE id=?",(session["user_id"],)).fetchone(); conn.close()
    message=None; error=None
    if request.method=="POST":
        action=request.form.get("action")
        if action=="send_sms" and user["phone"]:
            ok,msg=_send_sms_otp(user["phone"]); message=msg if ok else None; error=None if ok else msg
            if ok: session["phone_verify_started"]=True
        elif action=="verify_sms" and user["phone"]:
            ok,msg=_check_sms_otp(user["phone"],request.form.get("otp",""));
            if ok:
                conn=get_connection(); conn.execute("UPDATE users SET phone_verified=1 WHERE id=?",(session["user_id"],)); conn.commit(); conn.close(); user=dict(user); user["phone_verified"]=1; message=msg
            else: error=msg
        elif action=="send_email" and user["email"]:
            otp=str(secrets.randbelow(900000)+100000); session["email_verify_otp"]=otp; session["email_verify_expires"]=(datetime.utcnow()+timedelta(minutes=10)).isoformat()
            ok,msg=_send_email_otp(user["email"],otp); message=msg if ok else None; error=None if ok else msg
        elif action=="verify_email" and user["email"]:
            expires=session.get("email_verify_expires","")
            if not expires or datetime.utcnow() > datetime.fromisoformat(expires): error="Email OTP expired. Send a new code."
            elif request.form.get("otp","").strip()!=session.get("email_verify_otp"): error="Invalid email OTP."
            else:
                conn=get_connection(); conn.execute("UPDATE users SET email_verified=1 WHERE id=?",(session["user_id"],)); conn.commit(); conn.close(); session.pop("email_verify_otp",None); session.pop("email_verify_expires",None); user=dict(user); user["email_verified"]=1; message="Email verified successfully."
    return render_template("verify_contact.html",user=user,message=message,error=error)

@app.route("/forgot-password", methods=["GET","POST"])
def forgot_password():
    # Local/demo reset flow. No external SMS/email service is required.
    error=None; message=None
    if request.method=="POST":
        identity=request.form.get("identity","").strip()
        conn=get_connection()
        user=conn.execute("""SELECT id,username,email,phone FROM users
                             WHERE username=? OR email=? OR phone=? LIMIT 1""",
                          (identity,identity,identity)).fetchone()
        conn.close()
        if not user:
            error="No account was found for that username, email or phone number."
        else:
            otp=str(secrets.randbelow(900000)+100000)
            session["reset_user_id"]=user["id"]
            session["reset_otp"]=otp
            session["reset_expires"]=(datetime.utcnow()+timedelta(minutes=10)).isoformat()
            sent=False; channel=None
            if user["phone"]:
                sent,msg=_send_sms_otp(user["phone"])
                if sent: channel="sms"
            if user["email"] and not sent:
                sent,msg=_send_email_otp(user["email"],otp)
                if sent: channel="email"
            session["reset_channel"]=channel
            message=msg if sent else "Verification service is not configured for this account."
    return render_template("forgot_password.html",error=error,message=(message or session.get("reset_message")))

@app.route("/forgot-password/verify", methods=["GET","POST"])
def verify_otp():
    error=None; success=None
    if request.method=="POST":
        otp=request.form.get("otp","").strip()
        new=request.form.get("new_password","")
        expires=session.get("reset_expires","")
        valid_otp=False
        if session.get("reset_channel") == "sms":
            conn=get_connection(); reset_user=conn.execute("SELECT phone FROM users WHERE id=?",(session.get("reset_user_id"),)).fetchone(); conn.close()
            if reset_user:
                valid_otp, sms_message = _check_sms_otp(reset_user["phone"], otp)
                if not valid_otp: error=sms_message
        else:
            valid_otp = bool(session.get("reset_user_id")) and otp == session.get("reset_otp")
        if not valid_otp and not error:
            error="Invalid OTP."
        elif expires and datetime.utcnow() > datetime.fromisoformat(expires):
            error="OTP expired. Please request a new code."
        elif not _strong_password(new):
            error="Password must contain at least 10 characters with letters and numbers."
        else:
            conn=get_connection()
            conn.execute("UPDATE users SET password=? WHERE id=?",
                         (generate_password_hash(new),session["reset_user_id"]))
            conn.commit(); conn.close()
            session.pop("reset_user_id",None); session.pop("reset_otp",None); session.pop("reset_expires",None); session.pop("reset_channel",None); session.pop("reset_message",None)
            success="Password changed successfully. You can now log in."
    return render_template("verify_otp.html",error=error,success=success)

@app.route("/admin/reports/monthly")
def monthly_report():
    if not _require_role("admin"): return redirect(url_for("login"))
    month=request.args.get("month", date.today().strftime("%Y-%m"))
    conn=get_connection()
    report=conn.execute("""SELECT i.id,b.title AS book_title,b.author,b.category,users.full_name AS student_name,s.roll_no,s.course,s.semester,s.academic_year,
                                  i.issue_date,i.due_date,i.return_date,i.status,i.fine
                           FROM issues i JOIN books b ON b.id=i.book_id
                           JOIN students s ON s.id=i.student_id JOIN users ON users.id=s.user_id
                           WHERE substr(i.issue_date,1,7)=? ORDER BY i.issue_date DESC""",(month,)).fetchall()
    conn.close()
    return render_template("monthly_report.html",report=report,selected_month=month)

@app.route("/admin/reports/annual")
def annual_report():
    if not _require_role("admin"): return redirect(url_for("login"))
    year=request.args.get("year", date.today().year)
    conn=get_connection()
    report=conn.execute("""SELECT i.id,b.title AS book_title,b.author,b.category,users.full_name AS student_name,s.roll_no,s.course,s.semester,s.academic_year,
                                  i.issue_date,i.due_date,i.return_date,i.status,i.fine
                           FROM issues i JOIN books b ON b.id=i.book_id
                           JOIN students s ON s.id=i.student_id JOIN users ON users.id=s.user_id
                           WHERE substr(i.issue_date,1,4)=? ORDER BY i.issue_date DESC""",(str(year),)).fetchall()
    conn.close()
    return render_template("annual_report.html",report=report,selected_year=str(year),year=str(year))

@app.route("/admin/reports/semester")
def semester_report():
    if not _require_role("admin"): return redirect(url_for("login"))
    semester=request.args.get("semester","1")
    conn=get_connection()
    report=conn.execute("""SELECT i.id,b.title AS book_title,b.author,b.category,users.full_name AS student_name,s.roll_no,s.course,s.semester,s.academic_year,
                                  i.issue_date,i.due_date,i.return_date,i.status,i.fine
                           FROM issues i JOIN books b ON b.id=i.book_id
                           JOIN students s ON s.id=i.student_id JOIN users ON users.id=s.user_id
                           WHERE CAST(s.semester AS TEXT)=? ORDER BY i.issue_date DESC""",(str(semester),)).fetchall()
    conn.close()
    return render_template("semester_report.html",report=report,selected_semester=str(semester),semester=str(semester))

@app.route("/admin/reports/student")
def student_report():
    if not _require_role("admin"): return redirect(url_for("login"))
    roll_no=request.args.get("roll_no","").strip()
    conn=get_connection()
    report=conn.execute("""SELECT i.id,b.title AS book_title,b.author,b.category,users.full_name AS student_name,s.roll_no,s.course,s.semester,s.academic_year,
                                  i.issue_date,i.due_date,i.return_date,i.status,i.fine
                           FROM issues i JOIN books b ON b.id=i.book_id
                           JOIN students s ON s.id=i.student_id JOIN users ON users.id=s.user_id
                           WHERE (?='' OR s.roll_no=?) ORDER BY i.issue_date DESC""",(roll_no,roll_no)).fetchall()
    conn.close()
    return render_template("student_report.html",report=report,roll_no=roll_no,selected_roll_no=roll_no)

@app.route("/admin/reports/books")
def book_usage_report():
    if not _require_role("admin"): return redirect(url_for("login"))
    conn=get_connection()
    report=conn.execute("""SELECT b.title,b.author,b.category,COUNT(i.id) AS times_issued
                           FROM books b LEFT JOIN issues i ON i.book_id=b.id
                           GROUP BY b.id ORDER BY times_issued DESC,b.title""").fetchall()
    conn.close()
    return render_template("book_usage_report.html",report=report)

@app.route("/admin/reports/usage")
def complete_usage_report():
    if not _require_role("admin"): return redirect(url_for("login"))
    conn=get_connection()
    report=conn.execute("""SELECT i.id,b.title AS book_title,b.author,b.category,users.full_name AS student_name,s.roll_no,s.course,s.semester,s.academic_year,
                                  i.issue_date,i.due_date,i.return_date,i.status,i.fine
                           FROM issues i JOIN books b ON b.id=i.book_id
                           JOIN students s ON s.id=i.student_id JOIN users ON users.id=s.user_id
                           ORDER BY i.id DESC""").fetchall()
    conn.close()
    return render_template("library_reports.html", report=report)

@app.route("/admin/reports/annual/pdf")
@app.route("/admin/reports/monthly/pdf")
@app.route("/admin/reports/semester/pdf")
@app.route("/admin/reports/student/pdf")
@app.route("/admin/reports/books/pdf")
def report_print_view():
    if not _require_role("admin"): return redirect(url_for("login"))
    # Browser-printable fallback. It intentionally avoids external PDF/cloud services.
    return redirect(request.path.rsplit("/pdf",1)[0] + (("?" + request.query_string.decode()) if request.query_string else ""))

@app.route("/admin/reports/annual.pdf")
def annual_pdf_alias():
    return redirect(url_for("annual_report"))

@app.route("/student/notifications/read/<int:notification_id>", methods=["POST"])
def mark_notification_read(notification_id):
    if not _require_role("student"): return redirect(url_for("login"))
    conn=get_connection()
    conn.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?",
                 (notification_id,session["user_id"]))
    conn.commit(); conn.close()
    return redirect(url_for("student_notifications"))

@app.route("/student/notifications/read-all", methods=["POST"])
def mark_all_notifications_read():
    if not _require_role("student"): return redirect(url_for("login"))
    conn=get_connection()
    conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?",(session["user_id"],))
    conn.commit(); conn.close()
    return redirect(url_for("student_notifications"))

# Compatibility alias used by older templates.
@app.route("/admin/notices/delete/<int:notice_id>", methods=["POST"])
def delete_notice(notice_id):
    if not _require_role("admin"): return redirect(url_for("login"))
    conn=get_connection(); conn.execute("DELETE FROM notices WHERE id=?",(notice_id,)); conn.commit(); conn.close()
    return redirect(url_for("admin_notices"))



@app.route("/admin/librarians/delete/<int:librarian_id>", methods=["POST"])
def delete_librarian(librarian_id):
    if not _require_role("admin"):
        return redirect(url_for("login"))
    conn=get_connection()
    row=conn.execute("SELECT user_id FROM librarians WHERE id=?",(librarian_id,)).fetchone()
    if row:
        # Keep the audit trail while removing the librarian account.
        conn.execute("UPDATE librarian_activity SET librarian_id=NULL WHERE librarian_id=?",(librarian_id,))
        conn.execute("DELETE FROM librarians WHERE id=?",(librarian_id,))
        conn.execute("DELETE FROM users WHERE id=? AND role='librarian'",(row["user_id"],))
        conn.commit()
    conn.close()
    return redirect(url_for("manage_librarians"))


@app.errorhandler(404)
def page_not_found(error):
    return render_template("feature_hub.html",
                           title="Page Not Found",
                           page_title="Page Not Found",
                           features=[
                               ("🏠","Go to Dashboard","Return to your main library dashboard",
                                "/admin" if session.get("role")=="admin" else ("/librarian" if session.get("role")=="librarian" else "/student")),
                               ("📚","Books","Open the library books section","/admin/books" if session.get("role") in ("admin","librarian") else "/student/books"),
                               ("🗞️","Magazines","Browse magazine resources","/admin/magazines" if session.get("role") in ("admin","librarian") else "/magazines")
                           ]), 404

if __name__ == "__main__":

    init_database()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=os.getenv("LIBRARY_DEBUG", "0") == "1"
    )


# ============================================================
# ANDROID API ROUTES
# ============================================================

