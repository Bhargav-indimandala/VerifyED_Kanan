"""
VerifyEd – OTP Service
Generates 6-digit OTPs and sends them via SMTP (or prints to console as fallback).
"""
import random
import smtplib
import json
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import Config


def generate_otp() -> str:
    """Return a random 6-digit OTP string."""
    return f"{random.randint(100000, 999999)}"


def send_otp_email(to_email: str, otp: str, full_name: str = '', subject: str = '') -> bool:
    """
    Send the OTP to `to_email`.
    Returns True on success, False on failure.
    If MAIL_USERNAME is not configured, prints OTP to console (dev mode).
    """
    subject = subject or "VerifyEd – Your Email Verification Code"
    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;background:#0f172a;
                border-radius:16px;padding:32px;color:#e2e8f0;">
      <div style="text-align:center;margin-bottom:24px;">
        <span style="font-size:28px;font-weight:900;
          background:linear-gradient(135deg,#818cf8,#34d399);
          -webkit-background-clip:text;-webkit-text-fill-color:transparent;">
          VerifyEd
        </span>
      </div>
      <h2 style="color:#fff;font-size:20px;margin-bottom:8px;">
        Hi {full_name or 'there'} 👋
      </h2>
      <p style="color:#94a3b8;font-size:14px;margin-bottom:24px;">
        Use the code below to verify your email and complete your registration.
        This code expires in <strong style="color:#f8fafc;">{Config.OTP_EXPIRY_MINUTES} minutes</strong>.
      </p>
      <div style="background:#1e293b;border-radius:12px;padding:24px;text-align:center;
                  border:1px solid #334155;margin-bottom:24px;">
        <span style="font-size:42px;font-weight:900;letter-spacing:12px;color:#818cf8;">
          {otp}
        </span>
      </div>
      <p style="color:#64748b;font-size:12px;text-align:center;">
        If you did not request this, you can safely ignore this email.
      </p>
    </div>
    """
    text_body = f"Your VerifyEd verification code is: {otp}\n\nExpires in {Config.OTP_EXPIRY_MINUTES} minutes."

    # ── Dev / no-SMTP fallback ────────────────────────────────────────────────
    if not Config.MAIL_USERNAME:
        print(f"\n  📧  [DEV] OTP for {to_email}: {otp}  (expires in {Config.OTP_EXPIRY_MINUTES} min)\n")
        return True

    # ── Real SMTP send ────────────────────────────────────────────────────────
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = Config.MAIL_DEFAULT_SENDER
        msg['To']      = to_email
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT, timeout=10) as server:
            if Config.MAIL_USE_TLS:
                server.starttls()
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.sendmail(Config.MAIL_DEFAULT_SENDER, [to_email], msg.as_string())
        return True
    except Exception as exc:
        print(f"  ❌  SMTP error: {exc}")
        # Fallback to console so demo still works
        print(f"  📧  [FALLBACK] OTP for {to_email}: {otp}")
        return False


def is_otp_valid(token, otp_entered: str) -> bool:
    """Check OTPToken row: not used, not expired, code matches."""
    if token.used:
        return False
    expiry = token.created_at + timedelta(minutes=Config.OTP_EXPIRY_MINUTES)
    if datetime.utcnow() > expiry:
        return False
    return token.otp == otp_entered.strip()
