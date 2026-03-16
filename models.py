from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name     = db.Column(db.String(200), default='')
    role          = db.Column(db.String(20), default='student')   # student | admin
    is_verified   = db.Column(db.Boolean, default=False)
    is_active_acc = db.Column(db.Boolean, default=True)           # admin can deactivate
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    documents     = db.relationship('Document', backref='owner', lazy=True,
                                    foreign_keys='Document.user_id')
    notifications = db.relationship('Notification', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Flask-Login uses get_id() → is_active property
    @property
    def is_active(self):
        return self.is_active_acc

    @property
    def document_progress(self):
        from config import Config
        total    = len(Config.REQUIRED_DOCUMENTS)
        uploaded = len({d.doc_type for d in self.documents} & set(Config.REQUIRED_DOCUMENTS))
        pct      = int((uploaded / total) * 100) if total else 0
        return uploaded, total, pct

    @property
    def verified_count(self):
        return sum(1 for d in self.documents if d.status == 'verified')


class OTPToken(db.Model):
    """Multi-purpose OTP: signup, forgot-password, email-change."""
    __tablename__ = 'otp_tokens'

    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(120), nullable=False, index=True)
    purpose    = db.Column(db.String(30), default='signup')  # signup|forgot_password|email_change
    otp        = db.Column(db.String(6), nullable=False)
    user_data  = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used       = db.Column(db.Boolean, default=False)


class Document(db.Model):
    __tablename__ = 'documents'

    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doc_type          = db.Column(db.String(50), nullable=False)
    filename          = db.Column(db.String(256), nullable=False)
    original_filename = db.Column(db.String(256), nullable=False)
    file_size         = db.Column(db.Integer, default=0)
    file_hash         = db.Column(db.String(64), default='')
    mime_type         = db.Column(db.String(100), default='')
    upload_time       = db.Column(db.DateTime, default=datetime.utcnow)
    status            = db.Column(db.String(30), default='processing')
    ai_summary        = db.Column(db.Text, default='')
    extracted_text    = db.Column(db.Text, default='')
    extracted_data    = db.Column(db.Text, default='{}')
    verification_notes= db.Column(db.Text, default='')
    admin_notes       = db.Column(db.Text, default='')

    # Enhanced AI fields
    authenticity_score = db.Column(db.Integer, default=0)   # 0-100
    tamper_flags       = db.Column(db.Text, default='[]')    # JSON list of flags
    metadata_json      = db.Column(db.Text, default='{}')    # file metadata

    verification_logs = db.relationship('VerificationLog', backref='document', lazy=True)

    @property
    def status_color(self):
        return {
            'verified':'emerald','needs_review':'amber','invalid':'red',
            'missing_info':'orange','processing':'blue','rejected':'red',
        }.get(self.status, 'gray')

    @property
    def status_label(self):
        return {
            'verified':'Verified','needs_review':'Needs Review','invalid':'Invalid Format',
            'missing_info':'Missing Information','processing':'Processing','rejected':'Rejected',
        }.get(self.status, 'Unknown')


class Notification(db.Model):
    __tablename__ = 'notifications'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message    = db.Column(db.Text, nullable=False)
    type       = db.Column(db.String(20), default='info')
    read       = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class VerificationLog(db.Model):
    __tablename__ = 'verification_logs'

    id           = db.Column(db.Integer, primary_key=True)
    document_id  = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    action       = db.Column(db.String(50), nullable=False)
    details      = db.Column(db.Text, default='')
    performed_by = db.Column(db.String(100), default='system')
    timestamp    = db.Column(db.DateTime, default=datetime.utcnow)
