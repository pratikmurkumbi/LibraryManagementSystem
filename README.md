#  Digital Library Management System

Flask + SQLite college library management system.

## Included modules
- Admin, librarian and student login
- Books, students and librarians
- Issue and return workflow
- Reservations and library history
- College events, notices and notifications
- E-Books with PDF upload and browser reader
- Journals with volume, issue, publisher and PDF
- College magazines
- Reports, analytics, departments and book categories
- Responsive desktop/mobile UI
- Library-themed backgrounds and replaceable college-photo placeholder

## Database tables
users, students, librarians, books, issues, reservations, events, notices,
notifications, magazines, ebooks, journals, digital_bookmarks,
digital_read_history, departments, book_categories, branches, librarian_activity

## Windows
Double-click `setup_and_run.bat`.

If you need to create/update an administrator manually:
`python create_admin.py`

## College branding
The current design uses `static/images/backgrounds/college-placeholder.svg`.
Later, your real college photograph and logo can be added without changing the application structure.

## Digital files
Only upload PDFs and other digital materials that the college is legally permitted to distribute.
