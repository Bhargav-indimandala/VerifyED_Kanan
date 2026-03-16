# VerifyEd – AI Student Document Verification System

A hackathon-ready MVP web application for students applying to study abroad to upload and verify their admission documents using AI.

## Features

- **Student Dashboard** – Upload documents, track application progress, receive notifications
- **AI Document Analysis** – OCR text extraction + intelligent analysis (GPAs, passport numbers, IELTS scores, etc.)
- **Verification Engine** – Automated file and content checks with status assignment
- **Admin Panel** – View all users, review documents, approve/reject with notes
- **Secure Auth** – Login, signup, logout with Werkzeug password hashing

## Tech Stack

| Layer       | Technology                          |
|-------------|--------------------------------------|
| Frontend    | HTML5, TailwindCSS, JavaScript       |
| Backend     | Python, Flask                        |
| AI          | Google Gemini API (optional), OCR    |
| Database    | SQLite + SQLAlchemy                  |
| Auth        | Flask-Login + Werkzeug               |

## Quick Start

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. (Optional) Set Gemini API key for AI analysis

```bash
# Windows PowerShell
$env:GEMINI_API_KEY = "your-gemini-api-key"

# Linux/Mac
export GEMINI_API_KEY="your-gemini-api-key"
```

> Without an API key, the system uses intelligent rule-based analysis (regex patterns for passports, GPAs, IELTS scores, etc.) which works great for demos.

### 3. Run the application

```bash
python app.py
```

The app will start at **http://127.0.0.1:5000**

### 4. Default credentials

| Role    | Username | Password  |
|---------|----------|-----------|
| Admin   | admin    | admin123  |

Students register via the signup page.

## Project Structure

```
/project
├── app.py                  # Flask application + routes
├── config.py               # Configuration
├── models.py               # SQLAlchemy models
├── ai_engine.py            # AI analysis engine
├── verification.py         # Document verification checks
├── requirements.txt        # Dependencies
├── templates/              # Jinja2 HTML templates
│   ├── base.html
│   ├── landing.html
│   ├── login.html
│   ├── signup.html
│   ├── student_dashboard.html
│   ├── upload.html
│   ├── document_detail.html
│   ├── admin_dashboard.html
│   ├── admin_user_detail.html
│   └── error.html
├── static/
│   ├── css/style.css       # Custom styles
│   └── js/main.js          # Frontend JS
├── uploads/                # Uploaded files
└── database/               # SQLite database
```

## Document Types

| Document             | AI Extraction                          |
|----------------------|----------------------------------------|
| Passport             | Name, passport number, expiry date     |
| Academic Transcript  | GPA, university, degree program        |
| IELTS/TOEFL          | Test type, overall score, sections     |
| Statement of Purpose | Word count, key themes, writing quality|
| Resume / CV          | Skills, education, contact info        |
| Recommendation Letter| Strength rating, positive descriptors  |

## Demo Workflow

1. Sign up as a student at `/signup`
2. Upload a passport PDF → system extracts name and detects passport number
3. Upload a transcript → GPA and university detected
4. Check dashboard → progress bar shows completion percentage
5. Log in as admin (`admin` / `admin123`) → view all students and documents
6. Admin approves or rejects documents → student receives notifications
