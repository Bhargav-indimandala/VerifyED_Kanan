"""
VerifyEd – Main Flask Application  (enhanced)

New / fixed in this revision
─────────────────────────────
•  OTP email-verification required at signup (OTPToken model)
•  secure_filename() on every upload (path traversal fix)
•  SHA-256 duplicate-hash detection wired into VerificationEngine
•  Admin re-verify endpoint  (/admin/document/<id>/reverify)
•  Admin search/filter students
•  Missing-doc notification sent on dashboard load (triggered logic)
•  IELTS "Overall Band Score" regex fixed  (ai_engine.py)
•  Passport name extraction greedy-match fixed (ai_engine.py)
•  Stronger default admin password in config
•  init_db() called at module level so WSGI servers work
"""

# Load .env file automatically on every startup — credentials set once, work forever
from dotenv import load_dotenv
load_dotenv()

import csv
import hashlib
import io
import json
import os
import uuid
from datetime import datetime

from flask import (Flask, render_template, redirect, url_for, flash,
                   request, jsonify, send_from_directory, abort, session,
                   Response)
from flask_login import (LoginManager, login_user, logout_user,
                          login_required, current_user)
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from config import Config
from models import db, User, Document, Notification, VerificationLog, OTPToken
from ai_engine import AIEngine
from verification import VerificationEngine
from otp_service import generate_otp, send_otp_email, is_otp_valid

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.init_app(app)

ai_engine = AIEngine(api_key=Config.GEMINI_API_KEY)
verifier  = VerificationEngine()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def allowed_file(filename: str) -> bool:
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


def create_notification(user_id: int, message: str, ntype: str = 'info'):
    n = Notification(user_id=user_id, message=message, type=ntype)
    db.session.add(n)
    db.session.commit()


def ensure_dirs():
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'database'), exist_ok=True)


def _run_verification(doc: Document, file_path: str, doc_type: str) -> dict:
    """Run AI + verification engine and update doc in-place. Returns vresult."""
    try:
        analysis = ai_engine.analyze_document(file_path, doc_type)
    except Exception as exc:
        analysis = {
            'summary': f'Analysis failed: {exc}',
            'extracted_data': {}, 'quality_score': 0,
            'issues': [str(exc)], 'doc_type_confirmed': doc_type,
            'extracted_text': '',
        }

    doc.ai_summary    = analysis.get('summary', '')
    doc.extracted_text = analysis.get('extracted_text', '')
    doc.extracted_data = json.dumps(analysis.get('extracted_data', {}))

    # Collect existing hashes for this user (for duplicate detection)
    existing_hashes = [
        d.file_hash for d in
        Document.query.filter_by(user_id=doc.user_id)
                      .filter(Document.id != doc.id)
                      .all()
        if d.file_hash
    ]

    vresult = verifier.verify(
        file_path, doc_type,
        analysis.get('extracted_text', ''),
        analysis,
        existing_hashes=existing_hashes,
    )
    doc.status             = vresult['status']
    doc.verification_notes = vresult['notes']
    doc.file_hash          = vresult.get('file_hash', '')
    doc.authenticity_score = vresult.get('authenticity_score', 0)
    doc.tamper_flags       = json.dumps(vresult.get('tamper_flags', []))
    db.session.commit()
    return vresult


# ---------------------------------------------------------------------------
# DB init – called at module level so gunicorn/WSGI works too
# ---------------------------------------------------------------------------

def init_db():
    ensure_dirs()
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username=Config.ADMIN_USERNAME).first()
        if not admin:
            admin = User(
                username=Config.ADMIN_USERNAME,
                email=Config.ADMIN_EMAIL,
                full_name='System Admin',
                role='admin',
                is_verified=True,
            )
            admin.set_password(Config.ADMIN_PASSWORD)
            db.session.add(admin)
            db.session.commit()
            print(f"  ✓ Admin created: {Config.ADMIN_USERNAME} / {Config.ADMIN_PASSWORD}")


init_db()


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.role == 'admin'
                        else url_for('dashboard'))
    return render_template('landing.html')


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.is_verified and user.role != 'admin':
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('verify_otp_page', email=user.email))
            # Regenerate session to prevent session fixation
            session.clear()
            login_user(user, remember=True)
            flash('Welcome back!', 'success')
            return redirect(url_for('admin_dashboard') if user.role == 'admin'
                            else url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        full_name= request.form.get('full_name', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        errors = []
        if len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if '@' not in email:
            errors.append('Please enter a valid email address.')
        if len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        if password != confirm:
            errors.append('Passwords do not match.')
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('signup.html',
                                   prefill={'username': username, 'email': email,
                                            'full_name': full_name})

        # Generate OTP and store pending user data
        otp  = generate_otp()
        token = OTPToken(
            email     = email,
            otp       = otp,
            user_data = json.dumps({
                'username':      username,
                'email':         email,
                'full_name':     full_name,
                'password_hash': generate_password_hash(password),
            }),
        )
        db.session.add(token)
        db.session.commit()

        sent = send_otp_email(email, otp, full_name)
        if sent:
            flash('A 6-digit verification code has been sent to your email.', 'info')
        else:
            flash('OTP sent (check server console in dev mode).', 'info')

        return redirect(url_for('verify_otp_page', email=email))

    return render_template('signup.html', prefill={})


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp_page():
    email = request.args.get('email', '') or request.form.get('email', '')

    if request.method == 'POST':
        otp_entered = ''.join([
            request.form.get(f'otp{i}', '') for i in range(1, 7)
        ]).strip()
        email = request.form.get('email', '').strip().lower()

        # Find latest unused token for this email
        token = (OTPToken.query
                         .filter_by(email=email, used=False)
                         .order_by(OTPToken.created_at.desc())
                         .first())

        if not token:
            flash('No pending verification found. Please sign up again.', 'error')
            return redirect(url_for('signup'))

        # Brute-force protection: max 5 attempts per email per session
        attempt_key = f'otp_attempts_{email}'
        attempts = session.get(attempt_key, 0) + 1
        session[attempt_key] = attempts
        if attempts > 5:
            # Invalidate the token so attacker must request a new OTP
            token.used = True
            db.session.commit()
            session.pop(attempt_key, None)
            flash('Too many incorrect attempts. Please request a new code.', 'error')
            return redirect(url_for('resend_otp_get', email=email))

        if not is_otp_valid(token, otp_entered):
            remaining = max(0, 5 - attempts)
            flash(f'Invalid or expired code. {remaining} attempt(s) remaining.', 'error')
            return render_template('verify_otp.html', email=email, attempts_left=remaining)

        # Mark token used and clear brute-force counter
        token.used = True
        db.session.commit()
        session.pop(f'otp_attempts_{email}', None)

        # Check if user already exists (e.g. resend flow)
        existing = User.query.filter_by(email=email).first()
        if existing:
            existing.is_verified = True
            db.session.commit()
            session.clear()
            login_user(existing, remember=True)
        else:
            # Create user from stored data
            data = json.loads(token.user_data)
            user = User(
                username      = data['username'],
                email         = data['email'],
                full_name     = data['full_name'],
                password_hash = data['password_hash'],
                role          = 'student',
                is_verified   = True,
            )
            db.session.add(user)
            db.session.commit()
            create_notification(user.id,
                                'Welcome to VerifyEd! Start by uploading your documents.',
                                'success')
            session.clear()
            login_user(user, remember=True)

        flash('Email verified! Welcome to VerifyEd 🎉', 'success')
        return redirect(url_for('dashboard'))

    return render_template('verify_otp.html', email=email)


@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    email = request.form.get('email', '').strip().lower()
    if not email:
        flash('Email not found.', 'error')
        return redirect(url_for('signup'))

    # Invalidate previous tokens
    OTPToken.query.filter_by(email=email, used=False).update({'used': True})
    db.session.commit()

    otp   = generate_otp()
    token = OTPToken(email=email, otp=otp)
    db.session.add(token)
    db.session.commit()

    send_otp_email(email, otp)
    flash('A new code has been sent to your email.', 'success')
    return redirect(url_for('verify_otp_page', email=email))


@app.route('/resend-otp-redirect')
def resend_otp_get():
    """GET redirect target after brute-force lockout — shows resend page."""
    email = request.args.get('email', '')
    return render_template('verify_otp.html', email=email, attempts_left=0, locked=True)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))


# ---------------------------------------------------------------------------
# Student routes
# ---------------------------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    documents     = Document.query.filter_by(user_id=current_user.id)\
                                  .order_by(Document.upload_time.desc()).all()
    notifications = Notification.query.filter_by(user_id=current_user.id, read=False)\
                                      .order_by(Notification.created_at.desc()).limit(10).all()

    doc_map = {}
    for d in documents:
        if d.doc_type not in doc_map:
            doc_map[d.doc_type] = d

    # ── Triggered logic: notify about missing required docs ────────────────
    uploaded_verified_types = {d.doc_type for d in documents if d.status == 'verified'}
    for key, label in Config.REQUIRED_DOCUMENTS.items():
        sess_key = f'notif_missing_{key}'
        if key in uploaded_verified_types:
            # Doc is now verified — clear the stale session flag so it
            # won't re-fire if the student later re-uploads a different doc type
            session.pop(sess_key, None)
        else:
            # Only fire once per session per missing doc
            if not session.get(sess_key):
                session[sess_key] = True
                # Check if there's already an unread notification for this
                exists = Notification.query.filter_by(
                    user_id=current_user.id, read=False
                ).filter(Notification.message.contains(label)).first()
                if not exists:
                    create_notification(
                        current_user.id,
                        f'📎 Reminder: Your {label} has not been verified yet.',
                        'warning',
                    )

    uploaded, total, progress = current_user.document_progress
    return render_template('student_dashboard.html',
                           documents=documents,
                           doc_map=doc_map,
                           notifications=notifications,
                           required_docs=Config.REQUIRED_DOCUMENTS,
                           uploaded=uploaded, total=total, progress=progress)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        doc_type = request.form.get('doc_type', '')
        file     = request.files.get('document')

        if not doc_type or doc_type not in Config.REQUIRED_DOCUMENTS:
            flash('Please select a valid document type.', 'error')
            return redirect(url_for('upload'))
        if not file or file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('upload'))
        if not allowed_file(file.filename):
            flash('Invalid file type. Allowed: PDF, PNG, JPG, DOC, DOCX.', 'error')
            return redirect(url_for('upload'))

        # secure_filename – prevents path traversal
        safe_name   = secure_filename(file.filename)
        ext         = safe_name.rsplit('.', 1)[1].lower()
        unique_name = f"{uuid.uuid4().hex}.{ext}"
        file_path   = os.path.join(Config.UPLOAD_FOLDER, unique_name)
        file.save(file_path)
        file_size = os.path.getsize(file_path)

        # Remove previous upload of same type for this user
        old = Document.query.filter_by(user_id=current_user.id, doc_type=doc_type).first()
        if old:
            old_path = os.path.join(Config.UPLOAD_FOLDER, old.filename)
            if os.path.exists(old_path):
                os.remove(old_path)
            VerificationLog.query.filter_by(document_id=old.id).delete()
            db.session.delete(old)
            db.session.commit()

        doc = Document(
            user_id           = current_user.id,
            doc_type          = doc_type,
            filename          = unique_name,
            original_filename = safe_name,
            file_size         = file_size,
            mime_type         = file.content_type or '',
            status            = 'processing',
        )
        db.session.add(doc)
        db.session.commit()

        vresult = _run_verification(doc, file_path, doc_type)

        log = VerificationLog(
            document_id  = doc.id,
            action       = 'auto_verify',
            details      = json.dumps(vresult['checks'], default=str),
            performed_by = 'system',
        )
        db.session.add(log)
        db.session.commit()

        label = Config.REQUIRED_DOCUMENTS.get(doc_type, doc_type)
        _notify_upload_result(current_user.id, label, doc.status, doc.verification_notes)

        flash(f'{label} uploaded and analysed! Status: {doc.status_label}', 'success')
        return redirect(url_for('dashboard'))

    return render_template('upload.html', required_docs=Config.REQUIRED_DOCUMENTS)


def _notify_upload_result(user_id, label, status, notes):
    msgs = {
        'verified':     (f'Your {label} has been verified successfully! ✅', 'success'),
        'needs_review': (f'Your {label} needs review: {notes}', 'warning'),
        'invalid':      (f'Your {label} was flagged as invalid: {notes}', 'error'),
    }
    msg, ntype = msgs.get(status, (f'Your {label} has missing information: {notes}', 'warning'))
    create_notification(user_id, msg, ntype)


@app.route('/document/<int:doc_id>')
@login_required
def view_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.user_id != current_user.id and current_user.role != 'admin':
        abort(403)
    logs = VerificationLog.query.filter_by(document_id=doc.id)\
                                .order_by(VerificationLog.timestamp.desc()).all()
    try:
        extracted = json.loads(doc.extracted_data)
    except Exception:
        extracted = {}
    return render_template('document_detail.html', doc=doc, logs=logs,
                           extracted=extracted,
                           required_docs=Config.REQUIRED_DOCUMENTS)


@app.route('/document/<int:doc_id>/delete', methods=['POST'])
@login_required
def delete_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.user_id != current_user.id:
        abort(403)
    fp = os.path.join(Config.UPLOAD_FOLDER, doc.filename)
    if os.path.exists(fp):
        os.remove(fp)
    VerificationLog.query.filter_by(document_id=doc.id).delete()
    db.session.delete(doc)
    db.session.commit()
    flash('Document deleted.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(Config.UPLOAD_FOLDER, filename)


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        abort(403)

    search  = request.args.get('q', '').strip()
    query   = User.query.filter_by(role='student')
    if search:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%'),
                User.full_name.ilike(f'%{search}%'),
            )
        )
    students   = query.order_by(User.created_at.desc()).all()
    total_docs     = Document.query.count()
    verified_docs  = Document.query.filter_by(status='verified').count()
    pending_docs   = Document.query.filter(
        Document.status.in_(['needs_review', 'processing', 'missing_info'])).count()
    recent_docs    = Document.query.order_by(Document.upload_time.desc()).limit(20).all()

    return render_template('admin_dashboard.html',
                           students=students,
                           total_students=User.query.filter_by(role='student').count(),
                           total_docs=total_docs,
                           verified_docs=verified_docs,
                           pending_docs=pending_docs,
                           recent_docs=recent_docs,
                           required_docs=Config.REQUIRED_DOCUMENTS,
                           search=search)


@app.route('/admin/user/<int:user_id>')
@login_required
def admin_user_detail(user_id):
    if current_user.role != 'admin':
        abort(403)
    user      = User.query.get_or_404(user_id)
    documents = Document.query.filter_by(user_id=user.id)\
                              .order_by(Document.upload_time.desc()).all()
    return render_template('admin_user_detail.html', student=user,
                           documents=documents,
                           required_docs=Config.REQUIRED_DOCUMENTS)


@app.route('/admin/document/<int:doc_id>/status', methods=['POST'])
@login_required
def admin_update_status(doc_id):
    if current_user.role != 'admin':
        abort(403)
    doc        = Document.query.get_or_404(doc_id)
    new_status = request.form.get('status', '')
    admin_notes= request.form.get('admin_notes', '')

    valid = ('verified', 'needs_review', 'invalid', 'missing_info', 'rejected')
    if new_status not in valid:
        flash('Invalid status.', 'error')
        return redirect(request.referrer or url_for('admin_dashboard'))

    old_status      = doc.status
    doc.status      = new_status
    doc.admin_notes = admin_notes
    db.session.commit()

    db.session.add(VerificationLog(
        document_id  = doc.id,
        action       = f'admin_{new_status}',
        details      = f'Changed {old_status} → {new_status}. Notes: {admin_notes}',
        performed_by = current_user.username,
    ))
    db.session.commit()

    label = Config.REQUIRED_DOCUMENTS.get(doc.doc_type, doc.doc_type)
    if new_status == 'verified':
        create_notification(doc.user_id, f'Your {label} has been approved! ✅', 'success')
    elif new_status == 'rejected':
        msg = f'Your {label} was rejected.'
        if admin_notes:
            msg += f' Reason: {admin_notes}'
        create_notification(doc.user_id, msg, 'error')
    else:
        create_notification(doc.user_id, f'Your {label} status updated to: {new_status}.', 'warning')

    flash(f'Document status updated to {new_status}.', 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))


@app.route('/admin/document/<int:doc_id>/reverify', methods=['POST'])
@login_required
def admin_reverify(doc_id):
    """Admin can trigger a fresh automated verification run."""
    if current_user.role != 'admin':
        abort(403)
    doc = Document.query.get_or_404(doc_id)
    file_path = os.path.join(Config.UPLOAD_FOLDER, doc.filename)
    if not os.path.exists(file_path):
        flash('File no longer exists on disk.', 'error')
        return redirect(request.referrer or url_for('admin_dashboard'))

    doc.status = 'processing'
    db.session.commit()

    vresult = _run_verification(doc, file_path, doc.doc_type)

    db.session.add(VerificationLog(
        document_id  = doc.id,
        action       = 'admin_reverify',
        details      = json.dumps(vresult['checks'], default=str),
        performed_by = current_user.username,
    ))
    db.session.commit()

    label = Config.REQUIRED_DOCUMENTS.get(doc.doc_type, doc.doc_type)
    create_notification(doc.user_id,
                        f'Your {label} has been re-verified by admin. Status: {doc.status_label}',
                        'info')
    flash(f'Re-verification complete. New status: {doc.status_label}', 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route('/api/notifications')
@login_required
def api_notifications():
    notifs = Notification.query.filter_by(user_id=current_user.id, read=False)\
                               .order_by(Notification.created_at.desc()).limit(20).all()
    return jsonify([{
        'id': n.id, 'message': n.message, 'type': n.type,
        'created_at': n.created_at.strftime('%Y-%m-%d %H:%M'),
    } for n in notifs])


@app.route('/api/notifications/<int:nid>/read', methods=['POST'])
@login_required
def api_mark_read(nid):
    n = Notification.query.get_or_404(nid)
    if n.user_id != current_user.id:
        abort(403)
    n.read = True
    db.session.commit()
    return jsonify({'ok': True})


@app.route('/api/notifications/read-all', methods=['POST'])
@login_required
def api_mark_all_read():
    Notification.query.filter_by(user_id=current_user.id, read=False).update({'read': True})
    db.session.commit()
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='Access denied.'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='Page not found.'), 404


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_profile':
            full_name = request.form.get('full_name', '').strip()
            email     = request.form.get('email', '').strip().lower()
            if '@' not in email:
                flash('Please enter a valid email address.', 'error')
            elif email != current_user.email and User.query.filter_by(email=email).first():
                flash('That email is already in use.', 'error')
            else:
                current_user.full_name = full_name
                current_user.email     = email
                db.session.commit()
                flash('Profile updated successfully.', 'success')

        elif action == 'change_password':
            cur_pw  = request.form.get('current_password', '')
            new_pw  = request.form.get('new_password', '')
            conf_pw = request.form.get('confirm_password', '')
            if not current_user.check_password(cur_pw):
                flash('Current password is incorrect.', 'error')
            elif len(new_pw) < 6:
                flash('New password must be at least 6 characters.', 'error')
            elif new_pw != conf_pw:
                flash('New passwords do not match.', 'error')
            else:
                current_user.set_password(new_pw)
                db.session.commit()
                flash('Password updated successfully.', 'success')

        return redirect(url_for('profile'))

    docs = Document.query.filter_by(user_id=current_user.id).all()
    uploaded, total, progress = current_user.document_progress
    stats = {
        'total':    len(docs),
        'verified': sum(1 for d in docs if d.status == 'verified'),
        'progress': progress,
    }
    return render_template('profile.html', stats=stats)


# ---------------------------------------------------------------------------
# Admin – CSV export
# ---------------------------------------------------------------------------

@app.route('/admin/export/students')
@login_required
def admin_export_students():
    if current_user.role != 'admin':
        abort(403)

    students = User.query.filter_by(role='student').order_by(User.created_at.desc()).all()
    output   = io.StringIO()
    writer   = csv.writer(output)
    writer.writerow(['ID', 'Username', 'Full Name', 'Email', 'Email Verified',
                     'Joined', 'Docs Uploaded', 'Docs Verified', 'Completion %'])
    for s in students:
        uploaded, total, pct = s.document_progress
        writer.writerow([s.id, s.username, s.full_name, s.email,
                         'Yes' if s.is_verified else 'No',
                         s.created_at.strftime('%Y-%m-%d'),
                         uploaded, s.verified_count, pct])

    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=verifyed_students.csv'})


@app.route('/admin/export/documents')
@login_required
def admin_export_documents():
    if current_user.role != 'admin':
        abort(403)

    docs   = Document.query.order_by(Document.upload_time.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Student', 'Email', 'Doc Type', 'Original Filename',
                     'Status', 'File Size (KB)', 'Uploaded', 'AI Summary'])
    for d in docs:
        writer.writerow([d.id, d.owner.username, d.owner.email,
                         Config.REQUIRED_DOCUMENTS.get(d.doc_type, d.doc_type),
                         d.original_filename, d.status,
                         round(d.file_size / 1024, 1),
                         d.upload_time.strftime('%Y-%m-%d %H:%M'),
                         (d.ai_summary or '')[:200]])

    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=verifyed_documents.csv'})
# Main
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Student – upload history timeline
# ---------------------------------------------------------------------------

@app.route('/api/timeline')
@login_required
def api_timeline():
    """Return chronological upload + status-change events for the student."""
    docs  = Document.query.filter_by(user_id=current_user.id)                          .order_by(Document.upload_time.desc()).all()
    logs  = (VerificationLog.query
             .join(Document, VerificationLog.document_id == Document.id)
             .filter(Document.user_id == current_user.id)
             .order_by(VerificationLog.timestamp.desc())
             .limit(40).all())

    events = []
    for d in docs:
        events.append({
            'time':    d.upload_time.strftime('%Y-%m-%d %H:%M'),
            'type':    'upload',
            'doc':     Config.REQUIRED_DOCUMENTS.get(d.doc_type, d.doc_type),
            'status':  d.status,
            'message': f'Uploaded {d.original_filename}',
        })
    for l in logs:
        label = Config.REQUIRED_DOCUMENTS.get(l.document.doc_type, l.document.doc_type)
        events.append({
            'time':    l.timestamp.strftime('%Y-%m-%d %H:%M'),
            'type':    'log',
            'doc':     label,
            'status':  l.action,
            'message': l.action.replace('_', ' ').title() + f' by {l.performed_by}',
        })

    events.sort(key=lambda e: e['time'], reverse=True)
    return jsonify(events[:30])


# ---------------------------------------------------------------------------
# Admin – bulk status update
# ---------------------------------------------------------------------------

@app.route('/admin/bulk-status', methods=['POST'])
@login_required
def admin_bulk_status():
    if current_user.role != 'admin':
        abort(403)
    doc_ids    = request.form.getlist('doc_ids')
    new_status = request.form.get('bulk_status', '')
    valid      = ('verified', 'needs_review', 'rejected')
    if not doc_ids or new_status not in valid:
        flash('Invalid bulk action.', 'error')
        return redirect(url_for('admin_dashboard'))

    updated = 0
    for did in doc_ids:
        doc = Document.query.get(int(did))
        if doc:
            old = doc.status
            doc.status = new_status
            db.session.add(VerificationLog(
                document_id  = doc.id,
                action       = f'bulk_{new_status}',
                details      = f'Bulk action: {old} → {new_status}',
                performed_by = current_user.username,
            ))
            label = Config.REQUIRED_DOCUMENTS.get(doc.doc_type, doc.doc_type)
            if new_status == 'verified':
                create_notification(doc.user_id, f'Your {label} was approved! ✅', 'success')
            elif new_status == 'rejected':
                create_notification(doc.user_id, f'Your {label} was rejected.', 'error')
            updated += 1
    db.session.commit()
    flash(f'{updated} document(s) updated to "{new_status}".', 'success')
    return redirect(url_for('admin_dashboard'))



# ---------------------------------------------------------------------------
# Forgot Password flow
# ---------------------------------------------------------------------------

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user  = User.query.filter_by(email=email).first()
        # Always show success to prevent email enumeration
        flash('If that email exists, a reset code has been sent.', 'info')
        if user:
            OTPToken.query.filter_by(email=email, purpose='forgot_password', used=False)                          .update({'used': True})
            db.session.commit()
            otp   = generate_otp()
            token = OTPToken(email=email, purpose='forgot_password', otp=otp,
                             user_data=json.dumps({'user_id': user.id}))
            db.session.add(token)
            db.session.commit()
            send_otp_email(email, otp, user.full_name or user.username,
                           subject='VerifyEd – Password Reset Code')
        return redirect(url_for('reset_password_page', email=email))
    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_page():
    email = request.args.get('email', '') or request.form.get('email', '')
    if request.method == 'POST':
        otp_entered = ''.join([request.form.get(f'otp{i}', '') for i in range(1, 7)]).strip()
        email       = request.form.get('email', '').strip().lower()
        new_pw      = request.form.get('new_password', '')
        confirm_pw  = request.form.get('confirm_password', '')

        if len(new_pw) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('reset_password.html', email=email)
        if new_pw != confirm_pw:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', email=email)

        # Brute-force protection
        attempt_key = f'reset_attempts_{email}'
        attempts    = session.get(attempt_key, 0) + 1
        session[attempt_key] = attempts
        if attempts > 5:
            flash('Too many attempts. Please request a new reset code.', 'error')
            return redirect(url_for('forgot_password'))

        token = (OTPToken.query.filter_by(email=email, purpose='forgot_password', used=False)
                               .order_by(OTPToken.created_at.desc()).first())
        if not token or not is_otp_valid(token, otp_entered):
            remaining = max(0, 5 - attempts)
            flash(f'Invalid or expired code. {remaining} attempt(s) left.', 'error')
            return render_template('reset_password.html', email=email)

        data = json.loads(token.user_data)
        user = db.session.get(User, data['user_id'])
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('forgot_password'))

        token.used = True
        user.set_password(new_pw)
        db.session.commit()
        session.pop(attempt_key, None)
        create_notification(user.id, 'Your password was reset successfully.', 'success')
        flash('Password reset! Please log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)


# ---------------------------------------------------------------------------
# Email-change OTP flow  (from profile page)
# ---------------------------------------------------------------------------

@app.route('/profile/request-email-change', methods=['POST'])
@login_required
def request_email_change():
    new_email = request.form.get('new_email', '').strip().lower()
    if '@' not in new_email:
        flash('Please enter a valid email address.', 'error')
        return redirect(url_for('profile'))
    if User.query.filter_by(email=new_email).first():
        flash('That email is already in use.', 'error')
        return redirect(url_for('profile'))

    OTPToken.query.filter_by(email=current_user.email, purpose='email_change', used=False)                  .update({'used': True})
    db.session.commit()
    otp   = generate_otp()
    token = OTPToken(email=current_user.email, purpose='email_change', otp=otp,
                     user_data=json.dumps({'new_email': new_email, 'user_id': current_user.id}))
    db.session.add(token)
    db.session.commit()
    send_otp_email(current_user.email, otp, current_user.full_name,
                   subject='VerifyEd – Email Change Verification')
    flash(f'A verification code has been sent to {current_user.email}. Enter it below.', 'info')
    return redirect(url_for('confirm_email_change'))


@app.route('/profile/confirm-email-change', methods=['GET', 'POST'])
@login_required
def confirm_email_change():
    if request.method == 'POST':
        otp_entered = ''.join([request.form.get(f'otp{i}', '') for i in range(1, 7)]).strip()

        attempt_key = f'ec_attempts_{current_user.id}'
        attempts    = session.get(attempt_key, 0) + 1
        session[attempt_key] = attempts
        if attempts > 5:
            flash('Too many incorrect attempts.', 'error')
            return redirect(url_for('profile'))

        token = (OTPToken.query
                         .filter_by(email=current_user.email, purpose='email_change', used=False)
                         .order_by(OTPToken.created_at.desc()).first())
        if not token or not is_otp_valid(token, otp_entered):
            remaining = max(0, 5 - attempts)
            flash(f'Invalid or expired code. {remaining} attempt(s) left.', 'error')
            return render_template('confirm_email_change.html')

        data      = json.loads(token.user_data)
        new_email = data['new_email']

        # Final check: still not taken
        if User.query.filter_by(email=new_email).first():
            flash('That email was taken by another account.', 'error')
            token.used = True
            db.session.commit()
            return redirect(url_for('profile'))

        token.used         = True
        current_user.email = new_email
        db.session.commit()
        session.pop(attempt_key, None)
        create_notification(current_user.id,
                            f'Your email has been updated to {new_email}.', 'success')
        flash('Email updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('confirm_email_change.html')


# ---------------------------------------------------------------------------
# Admin – delete user
# ---------------------------------------------------------------------------

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash('Cannot delete another admin account.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Delete all files on disk
    for doc in user.documents:
        fp = os.path.join(Config.UPLOAD_FOLDER, doc.filename)
        if os.path.exists(fp):
            try:
                os.remove(fp)
            except OSError:
                pass
        VerificationLog.query.filter_by(document_id=doc.id).delete()

    # Cascade delete in DB
    Document.query.filter_by(user_id=user.id).delete()
    Notification.query.filter_by(user_id=user.id).delete()
    OTPToken.query.filter_by(email=user.email).delete()
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{user.username}" and all their data have been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/toggle-active', methods=['POST'])
@login_required
def admin_toggle_active(user_id):
    """Suspend or re-activate a student account without deleting data."""
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash('Cannot suspend an admin account.', 'error')
        return redirect(url_for('admin_dashboard'))
    user.is_active_acc = not user.is_active_acc
    db.session.commit()
    state = 'activated' if user.is_active_acc else 'suspended'
    flash(f'Account "{user.username}" has been {state}.', 'success')
    return redirect(request.referrer or url_for('admin_dashboard'))

if __name__ == '__main__':
    ai_mode = 'Gemini AI' if Config.USE_AI else 'Rule-based (set GEMINI_API_KEY for AI)'
    print(f"\n  🎓 VerifyEd (enhanced) is running!")
    print(f"  📍 http://127.0.0.1:5000")
    print(f"  🤖 Analysis mode : {ai_mode}")
    print(f"  👤 Admin login   : {Config.ADMIN_USERNAME} / {Config.ADMIN_PASSWORD}")
    print(f"  📧 OTP mode      : {'SMTP (' + Config.MAIL_USERNAME + ')' if Config.MAIL_USERNAME else 'Console (dev)'}\n")
    app.run(debug=True, port=5000)

