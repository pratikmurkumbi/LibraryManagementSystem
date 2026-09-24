#!/usr/bin/env python3
"""Create an administrator account for a fresh Library Management System database."""
import argparse
from database.database import get_connection, init_database
from werkzeug.security import generate_password_hash

parser = argparse.ArgumentParser(description="Create a Library Management System admin")
parser.add_argument("username")
parser.add_argument("password")
parser.add_argument("full_name")
args = parser.parse_args()

if len(args.password) < 10:
    raise SystemExit("Password must contain at least 10 characters.")

init_database()
conn = get_connection()
try:
    if conn.execute("SELECT 1 FROM users WHERE username=?", (args.username,)).fetchone():
        raise SystemExit("Username already exists.")
    conn.execute(
        "INSERT INTO users(username,password,full_name,role) VALUES(?,?,?,'admin')",
        (args.username, generate_password_hash(args.password), args.full_name),
    )
    conn.commit()
    print("Admin created successfully.")
    print(f"Username: {args.username}")
    print("Role: admin")
finally:
    conn.close()
