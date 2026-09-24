import sqlite3
import os

# Keep the database beside the project even when Flask is started from another directory.
DATABASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "library.db")


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_database():
    conn = get_connection()

    # Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    # Upgrade existing users table with profile/contact fields
    user_columns = [row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
    for column, definition in [
        ("profile_image", "TEXT"),
        ("phone", "TEXT"),
        ("email", "TEXT"),
        ("must_change_password", "INTEGER DEFAULT 0"),
        ("email_verified", "INTEGER DEFAULT 0"),
        ("phone_verified", "INTEGER DEFAULT 0"),
    ]:
        if column not in user_columns:
            conn.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")

    # Books table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            category TEXT,
            isbn TEXT,
            quantity INTEGER DEFAULT 1
        )
    """)

    # Upgrade existing books table with cover image support.
    book_columns = [row["name"] for row in conn.execute("PRAGMA table_info(books)").fetchall()]
    if "image" not in book_columns:
        conn.execute("ALTER TABLE books ADD COLUMN image TEXT")

    # Students table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            roll_no TEXT UNIQUE,
            course TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Upgrade existing students table with newer profile fields
    student_columns = [row["name"] for row in conn.execute("PRAGMA table_info(students)").fetchall()]
    for column, definition in [
        ("semester", "INTEGER"),
        ("academic_year", "TEXT"),
        ("profile_image", "TEXT"),
        ("department", "TEXT"),
    ]:
        if column not in student_columns:
            conn.execute(f"ALTER TABLE students ADD COLUMN {column} {definition}")

    # Librarians table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS librarians (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            employee_id TEXT UNIQUE,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Book issue table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            issue_date TEXT NOT NULL,
            return_date TEXT,
            status TEXT DEFAULT 'Issued',
            FOREIGN KEY (book_id) REFERENCES books(id),
            FOREIGN KEY (student_id) REFERENCES students(id)
        )
    """)

    # Add new columns to existing databases
    columns = conn.execute(
        "PRAGMA table_info(issues)"
    ).fetchall()

    column_names = [column["name"] for column in columns]

    if "due_date" not in column_names:
        conn.execute(
            "ALTER TABLE issues ADD COLUMN due_date TEXT"
        )

    if "fine" not in column_names:
        conn.execute(
            "ALTER TABLE issues ADD COLUMN fine REAL DEFAULT 0"
        )


    # Upgrade existing issues table with librarian tracking
    issue_columns = [row["name"] for row in conn.execute("PRAGMA table_info(issues)").fetchall()]
    if "librarian_id" not in issue_columns:
        conn.execute("ALTER TABLE issues ADD COLUMN librarian_id INTEGER")

    # Reservations table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            reservation_date TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            FOREIGN KEY (book_id) REFERENCES books(id),
            FOREIGN KEY (student_id) REFERENCES students(id)
        )
    """)

    # College Events table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            event_date TEXT NOT NULL,
            event_time TEXT,
            venue TEXT,
            image_filename TEXT,
            video_filename TEXT,
            created_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    """)

    # Add one sample college event on a fresh/empty events table
    # so the Events page is immediately visible after installation.
    existing_event = conn.execute("SELECT id FROM events LIMIT 1").fetchone()
    if existing_event is None:
        conn.execute("""
            INSERT INTO events
            (title, description, event_date, event_time, venue, image_filename, video_filename, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "College Annual Day 2026",
            "Join us for a day of cultural programs, technical activities, student performances and celebrations.",
            "2026-09-23",
            "10:00",
            "College Auditorium",
            "college_annual_day_sample.png",
            None,
            None
        ))

    # Admin accounts are created explicitly with create_admin.py.


    # ============================================================
    # DIGITAL LIBRARY TABLES
    # ============================================================
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ebooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT,
            category TEXT,
            isbn TEXT,
            publisher TEXT,
            publication_year TEXT,
            description TEXT,
            cover_image TEXT,
            pdf_file TEXT NOT NULL,
            uploaded_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS journals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            publisher TEXT,
            category TEXT,
            volume TEXT,
            issue TEXT,
            publication_year TEXT,
            description TEXT,
            cover_image TEXT,
            pdf_file TEXT,
            uploaded_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS magazines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            academic_year TEXT,
            semester TEXT,
            department TEXT,
            publication_date TEXT,
            cover_image TEXT,
            pdf_file TEXT,
            uploaded_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS digital_bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, resource_type, resource_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS digital_read_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id INTEGER NOT NULL,
            last_opened TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, resource_type, resource_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Notices / announcement board
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            notice_type TEXT DEFAULT 'General',
            created_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    """)

    # Notifications table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # Department master data
    conn.execute("""
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            code TEXT UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Book category master data
    conn.execute("""
        CREATE TABLE IF NOT EXISTS book_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Librarian audit trail
    conn.execute("""
        CREATE TABLE IF NOT EXISTS librarian_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            librarian_id INTEGER,
            action TEXT NOT NULL,
            description TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (librarian_id) REFERENCES librarians(id) ON DELETE SET NULL
        )
    """)

    # Optional branch master data retained for future branch-wise filtering.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS branches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            is_active INTEGER DEFAULT 1
        )
    """)

    # Useful indexes for search and dashboard queries.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_books_title ON books(title)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ebooks_title ON ebooks(title)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_journals_title ON journals(title)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_magazines_title ON magazines(title)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_issues_student_status ON issues(student_id, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, is_read)")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_database()
    print("Database created successfully!")
