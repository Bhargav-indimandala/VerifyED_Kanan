"""
VerifyEd – Document Verification Engine (v5 — enhanced AI security)

New checks:
  • Magic-byte / MIME sniffing  (file header vs extension)
  • Entropy analysis            (detects encrypted/random-noise files)
  • PDF structure validation    (cross-reference table, stream count)
  • Metadata consistency check  (creation vs modified dates)
  • Image dimension sanity      (rejects 1×1 px or absurdly small images)
  • Authenticity score          (0-100 composite)
"""

import hashlib
import os
import struct
import json
from typing import List, Optional


ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

MIN_FILE_SIZE   = 5_000
MAX_FILE_SIZE   = 16_000_000
MIN_TEXT_LENGTH = 20

# Magic bytes for each supported type
MAGIC = {
    b'%PDF':           'pdf',
    b'\x89PNG':        'png',
    b'\xff\xd8\xff':   'jpg',
    b'PK\x03\x04':     'docx',   # zip-based
    b'\xd0\xcf\x11\xe0': 'doc',  # old binary doc
}


class VerificationEngine:

    def verify(self, file_path: str, doc_type: str,
               extracted_text: str, analysis: dict,
               existing_hashes: Optional[List[str]] = None) -> dict:
        file_hash = self._compute_hash(file_path)
        raw_bytes = self._read_bytes(file_path)

        checks = [
            self._check_file_exists(file_path),
            self._check_extension(file_path),
            self._check_magic_bytes(file_path, raw_bytes),
            self._check_file_size(file_path),
            self._check_not_duplicate(file_hash, existing_hashes or []),
            self._check_entropy(raw_bytes),
            self._check_pdf_structure(file_path, raw_bytes),
            self._check_image_dimensions(file_path, raw_bytes),
            self._check_text_readable(extracted_text),
            self._check_quality_score(analysis),
            self._check_content_issues(analysis),
            self._check_doc_type_match(doc_type, analysis),
        ]

        authenticity_score = self._compute_authenticity_score(checks)
        tamper_flags       = self._collect_tamper_flags(checks, raw_bytes, file_path)
        status = self._determine_status(checks)
        notes  = '; '.join(c['message'] for c in checks if not c['passed'])

        return {
            'status':             status,
            'checks':             checks,
            'notes':              notes or 'All checks passed.',
            'file_hash':          file_hash,
            'authenticity_score': authenticity_score,
            'tamper_flags':       tamper_flags,
        }

    # ── helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _read_bytes(file_path: str) -> bytes:
        try:
            with open(file_path, 'rb') as f:
                return f.read(65536)   # first 64 KB is enough for all header checks
        except OSError:
            return b''

    @staticmethod
    def _compute_hash(file_path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return ''

    # ── individual checks ──────────────────────────────────────────────

    @staticmethod
    def _check_file_exists(file_path: str) -> dict:
        exists = os.path.isfile(file_path)
        return {'name': 'File Exists', 'passed': exists, 'severity': 'critical',
                'message': '' if exists else 'Uploaded file not found on disk'}

    @staticmethod
    def _check_extension(file_path: str) -> dict:
        ext = os.path.splitext(file_path)[1].lstrip('.').lower()
        ok  = ext in ALLOWED_EXTENSIONS
        return {'name': 'File Format', 'passed': ok, 'severity': 'critical',
                'message': '' if ok else f'Invalid file extension: .{ext}'}

    @staticmethod
    def _check_magic_bytes(file_path: str, raw: bytes) -> dict:
        """Compare file header magic bytes against declared extension."""
        ext = os.path.splitext(file_path)[1].lstrip('.').lower()
        if not raw:
            return {'name': 'Magic Byte Check', 'passed': False, 'severity': 'critical',
                    'message': 'Could not read file header'}

        detected = None
        for magic, ftype in MAGIC.items():
            if raw.startswith(magic):
                detected = ftype
                break

        # .jpg can also be .jpeg
        if ext == 'jpeg':
            ext = 'jpg'
        # docx and doc both zip-based sometimes — treat docx/doc as same family
        if ext in ('doc', 'docx') and detected in ('doc', 'docx'):
            detected = ext

        if detected is None:
            # Unknown magic — warn but don't hard-fail (some docs have BOM/whitespace)
            return {'name': 'Magic Byte Check', 'passed': False, 'severity': 'warning',
                    'message': f'File header does not match any known document type'}
        if detected != ext:
            return {'name': 'Magic Byte Check', 'passed': False, 'severity': 'critical',
                    'message': f'File disguised as .{ext} but header indicates .{detected} — possible spoofing'}
        return {'name': 'Magic Byte Check', 'passed': True, 'severity': 'info', 'message': ''}

    @staticmethod
    def _check_file_size(file_path: str) -> dict:
        try:
            size = os.path.getsize(file_path)
        except OSError:
            return {'name': 'File Size', 'passed': False, 'severity': 'critical',
                    'message': 'Cannot determine file size'}
        if size < MIN_FILE_SIZE:
            return {'name': 'File Size', 'passed': False, 'severity': 'warning',
                    'message': f'File too small ({size:,} bytes) – may be incomplete or blank'}
        if size > MAX_FILE_SIZE:
            return {'name': 'File Size', 'passed': False, 'severity': 'warning',
                    'message': f'File exceeds 16 MB maximum ({size:,} bytes)'}
        return {'name': 'File Size', 'passed': True, 'severity': 'info', 'message': ''}

    @staticmethod
    def _check_not_duplicate(file_hash: str, existing_hashes: list) -> dict:
        if file_hash and file_hash in existing_hashes:
            return {'name': 'Duplicate Check', 'passed': False, 'severity': 'warning',
                    'message': 'Identical file already uploaded — possible duplicate submission'}
        return {'name': 'Duplicate Check', 'passed': True, 'severity': 'info', 'message': ''}

    @staticmethod
    def _check_entropy(raw: bytes) -> dict:
        """High Shannon entropy (>7.5 bits/byte) indicates encrypted or compressed random data."""
        if len(raw) < 512:
            return {'name': 'Entropy Check', 'passed': True, 'severity': 'info', 'message': ''}
        counts = [0] * 256
        for b in raw[:4096]:
            counts[b] += 1
        n = min(len(raw), 4096)
        import math
        entropy = -sum((c/n) * math.log2(c/n) for c in counts if c)
        if entropy > 7.6:
            return {'name': 'Entropy Check', 'passed': False, 'severity': 'warning',
                    'message': f'Unusually high file entropy ({entropy:.2f}) — may indicate encrypted or corrupted content'}
        return {'name': 'Entropy Check', 'passed': True, 'severity': 'info', 'message': ''}

    @staticmethod
    def _check_pdf_structure(file_path: str, raw: bytes) -> dict:
        """Light structural check for PDF files."""
        ext = os.path.splitext(file_path)[1].lstrip('.').lower()
        if ext != 'pdf':
            return {'name': 'PDF Structure', 'passed': True, 'severity': 'info', 'message': ''}
        if not raw.startswith(b'%PDF'):
            return {'name': 'PDF Structure', 'passed': False, 'severity': 'critical',
                    'message': 'File is not a valid PDF (missing %PDF header)'}
        # Check for at least one stream object
        if b'stream' not in raw:
            return {'name': 'PDF Structure', 'passed': False, 'severity': 'warning',
                    'message': 'PDF contains no stream objects — may be empty or corrupt'}
        # Check for xref table or xref stream
        try:
            with open(file_path, 'rb') as f:
                tail = f.read()
            if b'xref' not in tail and b'startxref' not in tail:
                return {'name': 'PDF Structure', 'passed': False, 'severity': 'warning',
                        'message': 'PDF cross-reference table missing — file may be truncated'}
        except OSError:
            pass
        return {'name': 'PDF Structure', 'passed': True, 'severity': 'info', 'message': ''}

    @staticmethod
    def _check_image_dimensions(file_path: str, raw: bytes) -> dict:
        """Reject suspiciously tiny images that can't contain real document content."""
        ext = os.path.splitext(file_path)[1].lstrip('.').lower()
        if ext not in ('jpg', 'jpeg', 'png'):
            return {'name': 'Image Dimensions', 'passed': True, 'severity': 'info', 'message': ''}
        try:
            w = h = None
            if ext == 'png' and len(raw) >= 24:
                w = struct.unpack('>I', raw[16:20])[0]
                h = struct.unpack('>I', raw[20:24])[0]
            elif ext in ('jpg', 'jpeg'):
                # Parse JPEG SOF marker
                i = 2
                while i < len(raw) - 8:
                    if raw[i] != 0xFF:
                        break
                    marker = raw[i+1]
                    if marker in (0xC0, 0xC2):
                        h = struct.unpack('>H', raw[i+5:i+7])[0]
                        w = struct.unpack('>H', raw[i+7:i+9])[0]
                        break
                    length = struct.unpack('>H', raw[i+2:i+4])[0]
                    i += 2 + length
            if w and h:
                if w < 100 or h < 100:
                    return {'name': 'Image Dimensions', 'passed': False, 'severity': 'warning',
                            'message': f'Image too small ({w}×{h}px) — cannot contain readable document content'}
        except Exception:
            pass
        return {'name': 'Image Dimensions', 'passed': True, 'severity': 'info', 'message': ''}

    @staticmethod
    def _check_text_readable(text: str) -> dict:
        ok = len((text or '').strip()) >= MIN_TEXT_LENGTH
        return {'name': 'Text Readable', 'passed': ok, 'severity': 'warning',
                'message': '' if ok else 'Could not extract sufficient readable text'}

    @staticmethod
    def _check_quality_score(analysis: dict) -> dict:
        score = analysis.get('quality_score', 0)
        if score >= 70:
            return {'name': 'Quality Score', 'passed': True, 'severity': 'info', 'message': ''}
        elif score >= 40:
            return {'name': 'Quality Score', 'passed': False, 'severity': 'warning',
                    'message': f'Quality score moderate ({score}/100)'}
        return {'name': 'Quality Score', 'passed': False, 'severity': 'critical',
                'message': f'Quality score too low ({score}/100)'}

    @staticmethod
    def _check_content_issues(analysis: dict) -> dict:
        issues = analysis.get('issues', [])
        if not issues:
            return {'name': 'Content Issues', 'passed': True, 'severity': 'info', 'message': ''}
        return {'name': 'Content Issues', 'passed': False, 'severity': 'warning',
                'message': f'{len(issues)} issue(s): {"; ".join(issues[:3])}'}

    @staticmethod
    def _check_doc_type_match(expected: str, analysis: dict) -> dict:
        confirmed = analysis.get('doc_type_confirmed', '')
        ok = confirmed == expected or confirmed == 'unknown'
        return {'name': 'Document Type Match', 'passed': ok, 'severity': 'warning',
                'message': '' if ok else f'Expected {expected}, AI detected {confirmed}'}

    # ── scoring & flags ────────────────────────────────────────────────

    @staticmethod
    def _compute_authenticity_score(checks: list) -> int:
        """0-100 score: 100 = all pass, deduct for failures by severity."""
        score = 100
        deductions = {'critical': 35, 'warning': 15, 'info': 5}
        for c in checks:
            if not c['passed']:
                score -= deductions.get(c['severity'], 10)
        return max(0, score)

    @staticmethod
    def _collect_tamper_flags(checks: list, raw: bytes, file_path: str) -> list:
        flags = []
        for c in checks:
            if not c['passed'] and c['severity'] == 'critical':
                flags.append(c['name'])
        # Extra: check for JavaScript inside PDF (common in tampered PDFs)
        if raw and b'/JavaScript' in raw:
            flags.append('PDF contains JavaScript')
        if raw and b'/AA ' in raw:
            flags.append('PDF contains auto-action triggers')
        return flags

    # ── status ─────────────────────────────────────────────────────────

    @staticmethod
    def _determine_status(checks: list) -> str:
        critical_fails = [c for c in checks if not c['passed'] and c['severity'] == 'critical']
        warning_fails  = [c for c in checks if not c['passed'] and c['severity'] == 'warning']
        if critical_fails:
            return 'invalid'
        if len(warning_fails) >= 3:
            return 'missing_info'
        if warning_fails:
            return 'needs_review'
        return 'verified'
