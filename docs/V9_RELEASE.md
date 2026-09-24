# V9 Release

## Student management
- Circular student profile thumbnails in lists.
- Click a thumbnail to open a large photo viewer.
- Close with the X button, outside click, or Escape.
- Add student email and phone fields.
- Automatic secure temporary password generation.
- Force password change on first login.
- CSV bulk import for hundreds of students.
- Generated credentials CSV after bulk import.

## Verification
- Phone OTP integration through Twilio Verify.
- Email OTP integration through SMTP.
- Verification gate for student accounts.
- Password reset OTP expiration.

## Events
- Compact event cards.
- Small video previews instead of full-size videos in lists.
- Event detail page with full description, media and video player.
- Fixed admin event image/video upload field mismatch.

## Reports
- Redesigned report navigation with consistent cards and spacing.

## Security hardening
- Environment-based Flask secret key support.
- Secure session cookie settings.
- No automatic default administrator creation.
- Student API ownership checks.
- Stronger password policy.

## Data reset
V9 intentionally does not ship with `library.db`. Run `python reset_database.py`, start the application once, then create the first administrator with `python create_admin.py`.
