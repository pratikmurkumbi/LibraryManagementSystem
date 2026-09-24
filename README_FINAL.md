# Government Polytechnic Haliyal Library Management System

## Final unified UI release

This version keeps the local Flask + SQLite architecture and adds a consistent Library Pro interface for Admin, Librarian and Student screens.

### Main improvements
- Unified purple Library Pro UI
- Responsive desktop and mobile layout
- College logo and background placeholders
- Magazine and event themed backgrounds
- Page loading animation and card/hover animations
- Redesigned login and authentication pages
- Functional navigation for reports, reservations, notices, events, fines, profiles, notifications and password changes
- Local SQLite database, no Azure or external cloud database required
- Librarian access to book/digital-resource management pages used by the librarian dashboard
- Friendly fallback error page

## Windows PC

Double-click `Start_Library_System.bat`.

Or run manually:

```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000

## Phone / Termux

```bash
cd ~/LibraryManagement_UI_Final
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000

## College branding

Replace these placeholders later with your real college assets:

- `static/images/college-logo-placeholder.svg`
- `static/images/backgrounds/college-placeholder.svg`
- `static/images/backgrounds/library-hero.svg`
- `static/images/backgrounds/magazines.svg`
- `static/images/backgrounds/events.svg`

No database reset is required just to change the UI assets.
