#!/usr/bin/env python3
"""Delete the local SQLite database. The next app start recreates all tables."""
from pathlib import Path
from database.database import DATABASE
p = Path(DATABASE)
if p.exists():
    p.unlink()
    print(f"Deleted: {p}")
else:
    print("library.db is already reset (not present).")
print("Start the app once to recreate the database schema.")
