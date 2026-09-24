# Government Polytechnic Haliyal Library Management System V9

## Start on Windows

```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python reset_database.py
python app.py
```

In another Command Prompt:

```bat
.venv\Scripts\python create_admin.py admin "AdminV9Pass123" "System Administrator"
```

Then open `http://127.0.0.1:5000`.

For a real deployment, set `LIBRARY_SECRET_KEY` before starting the server.

## Start on Termux

```bash
cd ~/LibraryManagementSystem
python -m pip install -r requirements.txt
python reset_database.py
python app.py
```

Open another Termux session and run:

```bash
cd ~/LibraryManagementSystem
python create_admin.py admin 'AdminV9Pass123' 'System Administrator'
```

Then open `http://127.0.0.1:5000`.

## Student passwords

For a single student, leave the password field empty when creating the student. V9 generates a random temporary password. The student must change it at first login.

For hundreds of students, use **Students -> Import CSV**. V9 creates a different temporary password for every imported account and provides a credentials CSV.

## SMS verification

V9 is wired for Twilio Verify. Set these environment variables before starting Flask:

```text
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
TWILIO_VERIFY_SERVICE_SID=...
```

Phone numbers should be stored in international/E.164 form. Indian numbers can be entered as `9876543210`; V9 normalizes them to `+91...`.

## Email verification

Configure SMTP:

```text
SMTP_HOST=...
SMTP_PORT=587
SMTP_USER=...
SMTP_PASSWORD=...
SMTP_FROM=...
```

## Important

Do not put real SMS/email credentials in source files. Keep them in environment variables or a secure deployment secret store.
