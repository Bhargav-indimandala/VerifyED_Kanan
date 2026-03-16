# VerifyEd — AI Student Document Verification System

> A full-stack web application for study-abroad applicants to upload, verify, and track their admission documents — with automated AI authenticity checks, OTP email verification, and a complete admin panel.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Gmail SMTP Setup](#gmail-smtp-setup-real-otp-emails)
- [Document Types & AI Analysis](#document-types--ai-analysis)
- [Verification Engine](#verification-engine)
- [API Endpoints](#api-endpoints)
- [Demo Flow](#demo-flow)
- [Pushing to GitHub](#pushing-to-github)

---

## Features

### Student
- **Email OTP verification** on signup — account not created until email is confirmed
- **Forgot Password** — OTP-based reset sent directly to inbox
- **OTP-protected email change** — updating email requires confirming via current inbox
- **Document upload** — PDF, PNG, JPG, DOC, DOCX up to 16 MB with drag-and-drop
- **12-point AI verification** — runs automatically on every upload
- **Progress dashboard** — completion bar, per-document status, quick stats
- **Activity timeline** — chronological history of all uploads and status changes
- **Live notification badge** — unread count on navbar, auto-refreshes every 30 s
- **Password strength meter** on signup and reset forms
- **Profile page** — edit name, change password, change email (OTP-verified)

### Admin
- **Admin dashboard** — total students, documents, verified, and pending counts
- **Student search** — filter by name, email, or username in real time
- **Bulk actions** — select multiple documents → approve / needs-review / reject in one click
- **Re-verify** — re-run full AI + verification pipeline on any stored document
- **Manual status override** — approve, reject, or flag any document with notes
- **Delete user** — permanently removes account, documents, files, and notifications
- **Suspend / Activate** — lock an account without deleting any data
- **CSV export** — download all students or all documents as spreadsheets

### Security
- Session fixation protection on every login
- OTP brute-force protection — lockout after 5 wrong attempts
- `secure_filename()` on every upload — prevents path traversal
- SHA-256 duplicate detection — same file uploaded twice is flagged
- Magic-byte spoofing detection — PNG renamed to .pdf is caught
- PDF structure validation — missing headers, streams, xref tables flagged
- Entropy analysis — encrypted or random-noise files flagged
- JavaScript-in-PDF detection — malicious auto-action triggers caught
- Authenticity score (0–100) per document
- Tamper flags list per document

---

## Tech Stack

| Layer    | Technology |
|----------|------------|
| Backend  | Python 3.10+, Flask 3.1 |
| Database | SQLite + SQLAlchemy 2.0 + Flask-SQLAlchemy |
| Auth     | Flask-Login 0.6, Werkzeug password hashing |
| AI       | Google Gemini 2.0 Flash (optional) + rule-based fallback |
| OCR      | PyPDF2, Pillow, pytesseract |
| Email    | Python smtplib, Gmail SMTP |
| Config   | python-dotenv (.env file) |
| Frontend | Jinja2, TailwindCSS (CDN), Lucide Icons, Vanilla JS |

---

## Project Structure
```
VerifyEd/
├── app.py                         # Flask app — 30 routes
├── config.py                      # Config class (reads .env)
├── models.py                      # SQLAlchemy models
├── verification.py                # 12-check verification engine
├── ai_engine.py                   # Gemini AI + rule-based fallback
├── otp_service.py                 # OTP generate + SMTP send
├── requirements.txt
├── .env                           # ← YOUR CREDENTIALS (never commit)
├── .gitignore
│
├── templates/                     # 15 Jinja2 templates
│   ├── base.html
│   ├── landing.html
│   ├── login.html
│   ├── signup.html
│   ├── verify_otp.html
│   ├── forgot_password.html
│   ├── reset_password.html
│   ├── confirm_email_change.html
│   ├── student_dashboard.html
│   ├── upload.html
│   ├── document_detail.html
│   ├── profile.html
│   ├── admin_dashboard.html
│   ├── admin_user_detail.html
│   └── error.html
│
├── static/
│   ├── css/style.css
│   └── js/main.js
│
├── uploads/                       # uploaded files (auto-created)
└── database/                      # SQLite database (auto-created)
```

---

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip
- (Optional) Tesseract OCR for image documents → [install guide](https://github.com/tesseract-ocr/tesseract)

### 1 — Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/verifyed.git
cd verifyed
```

### 2 — Create a virtual environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac / Linux
python3 -m venv venv
source venv/bin/activate
```

### 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### 4 — Configure credentials

Open `.env` and fill in your values:
```env
SECRET_KEY=any-long-random-string-here
MAIL_USERNAME=your_gmail@gmail.com
MAIL_PASSWORD=your16charapppassword
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@verifyed.com
ADMIN_PASSWORD=Admin@123!
GEMINI_API_KEY=
```

> See [Gmail SMTP Setup](#gmail-smtp-setup-real-otp-emails) for how to get `MAIL_PASSWORD`.  
> Leave `GEMINI_API_KEY` blank — rule-based analysis works perfectly for demos.

### 5 — Run
```bash
python app.py
```

Open **http://127.0.0.1:5000**

On first run:
```
✓ Admin created: admin / Admin@123!
🎓 VerifyEd is running!
📍 http://127.0.0.1:5000
📧 OTP mode : SMTP (your_gmail@gmail.com)
```

### Default admin login

| Role  | Username | Password   |
|-------|----------|------------|
| Admin | `admin`  | `Admin@123!` |

Students self-register at `/signup`.

---

## Environment Variables

All variables live in `.env` — loaded automatically on every startup. You never set them in the terminal.

| Variable          | Required | Description |
|-------------------|----------|-------------|
| `SECRET_KEY`      | ✅       | Flask session key. Any long random string. |
| `MAIL_USERNAME`   | ✅       | Gmail address for OTP emails. |
| `MAIL_PASSWORD`   | ✅       | 16-char Gmail App Password (not your Gmail login password). |
| `ADMIN_USERNAME`  | Optional | Default: `admin` |
| `ADMIN_EMAIL`     | Optional | Default: `admin@verifyed.com` |
| `ADMIN_PASSWORD`  | Optional | Default: `Admin@123!` |
| `GEMINI_API_KEY`  | Optional | Enables Gemini AI analysis. Leave blank for rule-based. |

> **Dev mode:** If `MAIL_USERNAME` is blank, OTPs print to the terminal console instead of being emailed. Useful for local testing.

---

## Gmail SMTP Setup (Real OTP Emails)

### Step 1 — Enable 2-Step Verification
Go to **https://myaccount.google.com/security** → click **2-Step Verification** → turn it **ON**.

### Step 2 — Create an App Password
Go to **https://myaccount.google.com/apppasswords**

1. Type `VerifyEd` in the App name box
2. Click **Create**
3. Copy the 16-character password (e.g. `abcd efgh ijkl mnop`)
4. Remove all spaces → `abcdefghijklmnop`
5. Paste into `.env` as `MAIL_PASSWORD`

### Step 3 — Update `.env`
```env
MAIL_USERNAME=your_gmail@gmail.com
MAIL_PASSWORD=abcdefghijklmnop
```

### Step 4 — Restart
```bash
python app.py
# Should show: 📧 OTP mode : SMTP (your_gmail@gmail.com)
```

**Troubleshooting:**

| Error | Fix |
|-------|-----|
| `5.7.8 BadCredentials` | You used your Gmail login password — use the App Password instead |
| App Passwords page missing | 2-Step Verification not enabled |
| OTP in spam folder | Normal for first send — mark as Not Spam |

---

## Document Types & AI Analysis

| Document | Fields Extracted |
|----------|-----------------|
| Passport | Name, passport number, nationality, DOB, expiry date |
| Academic Transcript | GPA/CGPA, scale, university name, degree |
| English Test (IELTS/TOEFL) | Test type, overall score, flags if below threshold (IELTS 6.5 / TOEFL 80) |
| Statement of Purpose | Word count, key themes detected |
| Resume / CV | Email, phone, skills, education keywords |
| Recommendation Letter | Positive descriptors, strength rating (weak / moderate / strong) |

With `GEMINI_API_KEY` set → Gemini 2.0 Flash performs deep analysis.  
Without it → intelligent regex-based analyzers run automatically as fallback.

---

## Verification Engine

Every upload triggers **12 automated checks**:

| # | Check | What It Catches | Severity |
|---|-------|-----------------|----------|
| 1 | File Exists | File saved on disk | Critical |
| 2 | File Format | Extension in allowed list | Critical |
| 3 | Magic Byte Check | File disguised as wrong type | Critical |
| 4 | File Size | < 5 KB or > 16 MB | Warning |
| 5 | Duplicate Check | SHA-256 already in vault | Warning |
| 6 | Entropy Analysis | Encrypted / corrupted data | Warning |
| 7 | PDF Structure | Valid header, streams, xref table | Critical/Warning |
| 8 | Image Dimensions | Image too small for real content | Warning |
| 9 | Text Readable | Sufficient OCR/PDF text | Warning |
| 10 | Quality Score | AI confidence ≥ 70 | Critical/Warning |
| 11 | Content Issues | AI-detected problems | Warning |
| 12 | Document Type Match | Declared type matches AI detection | Warning |

Each document receives:
- **Status** — `verified` / `needs_review` / `missing_info` / `invalid`
- **Authenticity Score** — 0–100 composite
- **Tamper Flags** — list of specific anomalies

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/notifications` | Student | Fetch unread notifications |
| POST | `/api/notifications/<id>/read` | Student | Mark single notification read |
| POST | `/api/notifications/read-all` | Student | Mark all notifications read |
| GET | `/api/timeline` | Student | Activity timeline events |
| POST | `/admin/bulk-status` | Admin | Bulk update document statuses |
| GET | `/admin/export/students` | Admin | Download students CSV |
| GET | `/admin/export/documents` | Admin | Download documents CSV |

---

## Demo Flow

### Student
1. `/signup` → fill details → click **Continue – Send Verification Code**
2. Check email → enter 6-digit OTP
3. Redirected to `/dashboard`
4. Click **Upload Document** → select type → upload file
5. See verification results, authenticity score, and check breakdown instantly
6. Dashboard shows completion progress per document

### Admin
1. `/login` → `admin` / `Admin@123!`
2. View all students and document statistics
3. Click a student → see full checklist
4. Approve, reject, or re-verify documents
5. Bulk-select and update multiple documents at once
6. Export all data as CSV

---

## Pushing to GitHub

### First time
```bash
# 1. Initialise git
git init

# 2. Stage all files (.gitignore will exclude .env automatically)
git add .

# 3. VERIFY .env is NOT listed — it must not appear here
git status

# 4. First commit
git commit -m "Initial commit — VerifyEd AI Document Verification System"

# 5. Create a new EMPTY repo on github.com
#    Name: verifyed
#    Do NOT add README, .gitignore, or licence (you already have them)

# 6. Connect and push
git remote add origin https://github.com/YOUR_USERNAME/verifyed.git
git branch -M main
git push -u origin main
```

### Every future update
```bash
git add .
git commit -m "describe what changed"
git push
```

### Safety check before every push
```bash
git status
```

`.env` must **NOT** appear in the output.  
If it does:
```bash
git rm --cached .env
git commit -m "remove .env from tracking"
git push
```

---

## Security Notes

- **Never commit `.env`** — it contains your Gmail App Password
- Change `SECRET_KEY` to a long random string before public deployment
- Change `ADMIN_PASSWORD` from the default before going live
- For production, run behind Gunicorn + Nginx
- SQLite is fine for development; use PostgreSQL for production

---

## License

MIT — free to use, modify, and distribute.
