import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'verifyed-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'database', 'verifyed.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

    # AI Configuration
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
    USE_AI = bool(os.environ.get('GEMINI_API_KEY', ''))

    # Email / OTP (use SMTP or leave blank to use console fallback)
    MAIL_SERVER   = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT     = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS  = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')        # your Gmail address
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')        # app password
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_USERNAME', 'noreply@verifyed.com')
    OTP_EXPIRY_MINUTES  = 10                                   # OTP valid for 10 min

    # Document types required for a complete application
    REQUIRED_DOCUMENTS = {
        'passport':       'Passport',
        'transcript':     'Academic Transcript',
        'english_test':   'English Test Score (IELTS/TOEFL)',
        'sop':            'Statement of Purpose',
        'resume':         'Resume / CV',
        'recommendation': 'Recommendation Letter',
    }

    # Admin default credentials (created on first run)
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_EMAIL    = os.environ.get('ADMIN_EMAIL',    'admin@verifyed.com')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Admin@123!')
