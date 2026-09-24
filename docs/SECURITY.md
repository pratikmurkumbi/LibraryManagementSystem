# V9 Security Notes

## Authentication
- Passwords use Werkzeug password hashing.
- New administrator accounts are created explicitly with `create_admin.py`.
- New admin-created student accounts receive a random temporary password when the password field is left blank.
- Student accounts created by an administrator are required to change the temporary password on first login.
- Student accounts require email and phone verification before normal application access.

## OTP
- Phone verification uses Twilio Verify when the required environment variables are configured.
- Email verification uses SMTP when the required environment variables are configured.
- Password-reset OTPs expire after 10 minutes.
- Do not display OTPs in the web page in production.

## Deployment
- Set `LIBRARY_SECRET_KEY` to a strong random value.
- Set `LIBRARY_HTTPS=1` only when HTTPS is actually enabled.
- Keep Twilio and SMTP credentials outside source code.
- Do not commit `.env` or service credentials to version control.

## Student bulk import
The CSV import generates a unique random temporary password for every student and produces a credentials CSV for the administrator. Store that output securely and do not publish it.

## Remaining production work
- Add a full CSRF framework to every state-changing form/API request.
- Add a production-grade distributed rate limiter.
- Validate uploaded files by content/signature as well as extension.
- Add structured audit logging and backups.
- Use PostgreSQL if the system grows beyond the single-PC/small-campus SQLite use case.
