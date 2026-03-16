"""
VerifyEd – AI Document Analysis Engine

Extracts text from uploaded documents, analyzes content, and returns
structured data. Supports Gemini API when configured; otherwise falls back
to intelligent rule-based extraction.
"""

import json
import os
import re

# PDF text extraction
try:
    from PyPDF2 import PdfReader
except ImportError:
    PdfReader = None

# Image OCR
try:
    from PIL import Image
    import pytesseract
except ImportError:
    Image = None
    pytesseract = None

# Gemini AI
try:
    import google.generativeai as genai
except ImportError:
    genai = None


class AIEngine:
    """Handles document text extraction and AI analysis."""

    def __init__(self, api_key: str = ''):
        self.api_key = api_key
        self.use_ai = bool(api_key and genai)
        if self.use_ai:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-2.0-flash')

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_document(self, file_path: str, doc_type: str) -> dict:
        """Full pipeline: extract text → analyse → return results dict."""
        extracted_text = self.extract_text(file_path)

        if self.use_ai:
            try:
                result = self._ai_analyze(extracted_text, doc_type)
            except Exception:
                result = self._rule_based_analyze(extracted_text, doc_type)
        else:
            result = self._rule_based_analyze(extracted_text, doc_type)

        result['extracted_text'] = extracted_text[:5000]
        return result

    # ------------------------------------------------------------------
    # Text extraction
    # ------------------------------------------------------------------

    def extract_text(self, file_path: str) -> str:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.pdf':
            return self._extract_pdf(file_path)
        elif ext in ('.png', '.jpg', '.jpeg'):
            return self._extract_image(file_path)
        elif ext in ('.doc', '.docx'):
            return self._extract_docx(file_path)
        return ''

    @staticmethod
    def _extract_pdf(path: str) -> str:
        if PdfReader is None:
            return ''
        try:
            reader = PdfReader(path)
            pages = [p.extract_text() or '' for p in reader.pages]
            return '\n'.join(pages)
        except Exception:
            return ''

    @staticmethod
    def _extract_image(path: str) -> str:
        if Image is None or pytesseract is None:
            return ''
        try:
            img = Image.open(path)
            return pytesseract.image_to_string(img)
        except Exception:
            return ''

    @staticmethod
    def _extract_docx(path: str) -> str:
        # Minimal .docx reader – falls back gracefully
        try:
            import zipfile
            import xml.etree.ElementTree as ET
            with zipfile.ZipFile(path) as z:
                xml_content = z.read('word/document.xml')
            tree = ET.fromstring(xml_content)
            ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
            return '\n'.join(
                node.text for node in tree.iter(f'{{{ns["w"]}}}t') if node.text
            )
        except Exception:
            return ''

    # ------------------------------------------------------------------
    # Gemini AI analysis
    # ------------------------------------------------------------------

    def _ai_analyze(self, text: str, doc_type: str) -> dict:
        prompt = self._build_prompt(text, doc_type)
        response = self.model.generate_content(prompt)
        try:
            raw = response.text
            # Try to parse JSON from the response
            json_match = re.search(r'\{[\s\S]*\}', raw)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = {}
        except Exception:
            data = {}

        return {
            'summary': data.get('summary', response.text[:500]),
            'extracted_data': data.get('extracted_data', {}),
            'doc_type_confirmed': data.get('doc_type_confirmed', doc_type),
            'quality_score': data.get('quality_score', 70),
            'issues': data.get('issues', []),
        }

    @staticmethod
    def _build_prompt(text: str, doc_type: str) -> str:
        prompts = {
            'passport': (
                "Analyze this passport document text. Extract: full name, "
                "passport number, nationality, date of birth, expiry date. "
                "Check if the passport is expired."
            ),
            'transcript': (
                "Analyze this academic transcript. Extract: student name, "
                "university name, GPA/grades, degree program, graduation date. "
                "Assess academic performance."
            ),
            'english_test': (
                "Analyze this English proficiency test score document. "
                "Extract: test type (IELTS/TOEFL), overall score, individual "
                "section scores, test date. Check if score meets typical "
                "requirements (IELTS 6.5+ or TOEFL 80+)."
            ),
            'sop': (
                "Analyze this Statement of Purpose. Summarise the applicant's "
                "motivation, intended program, career goals, and key strengths. "
                "Assess writing quality."
            ),
            'resume': (
                "Analyze this resume/CV. Extract: name, education, skills, "
                "work experience, notable achievements. Summarise highlights."
            ),
            'recommendation': (
                "Analyze this recommendation letter. Extract: recommender name "
                "and title, relationship to applicant, key qualities praised. "
                "Assess the strength of the recommendation."
            ),
        }
        task = prompts.get(doc_type, "Analyze this document and extract key information.")
        return (
            f"{task}\n\nRespond ONLY with valid JSON containing keys: "
            f"summary, extracted_data (dict), doc_type_confirmed, "
            f"quality_score (0-100), issues (list of strings).\n\n"
            f"Document text:\n{text[:4000]}"
        )

    # ------------------------------------------------------------------
    # Rule-based fallback analysis
    # ------------------------------------------------------------------

    def _rule_based_analyze(self, text: str, doc_type: str) -> dict:
        analyzers = {
            'passport': self._analyze_passport,
            'transcript': self._analyze_transcript,
            'english_test': self._analyze_english_test,
            'sop': self._analyze_sop,
            'resume': self._analyze_resume,
            'recommendation': self._analyze_recommendation,
        }
        analyzer = analyzers.get(doc_type, self._analyze_generic)
        return analyzer(text)

    # --- Passport ---------------------------------------------------
    @staticmethod
    def _analyze_passport(text: str) -> dict:
        data = {}
        issues = []

        # Passport number (common patterns)
        pn = re.search(r'[A-Z]\d{7,8}', text)
        if pn:
            data['passport_number'] = pn.group()
        else:
            issues.append('Could not detect passport number')

        # Name (after fields like "Name" or "Surname")
        name_m = re.search(r'(?:name|surname)[:\s]+([A-Z][a-zA-Z ]+)', text, re.I)
        if name_m:
            data['name'] = name_m.group(1).strip()

        # Expiry
        exp = re.search(r'(?:expiry|expiration|valid until|date of expiry)[:\s]*(\d{2}[/\-\.]\d{2}[/\-\.]\d{2,4})', text, re.I)
        if exp:
            data['expiry_date'] = exp.group(1)
        else:
            issues.append('Could not detect expiry date')

        # DOB
        dob = re.search(r'(?:date of birth|dob|birth date)[:\s]*(\d{2}[/\-\.]\d{2}[/\-\.]\d{2,4})', text, re.I)
        if dob:
            data['date_of_birth'] = dob.group(1)

        # Nationality
        nat = re.search(r'(?:nationality|citizenship)[:\s]+([A-Za-z]+)', text, re.I)
        if nat:
            data['nationality'] = nat.group(1).strip()

        quality = 85 if len(data) >= 3 else (60 if data else 35)
        summary = f"Passport document analysed. Detected fields: {', '.join(data.keys()) or 'none'}."
        if issues:
            summary += f" Issues: {'; '.join(issues)}."

        return {
            'summary': summary,
            'extracted_data': data,
            'doc_type_confirmed': 'passport',
            'quality_score': quality,
            'issues': issues,
        }

    # --- Transcript -------------------------------------------------
    @staticmethod
    def _analyze_transcript(text: str) -> dict:
        data = {}
        issues = []

        gpa = re.search(r'(?:gpa|grade point|cgpa|cumulative)[:\s]*(\d+\.?\d*)\s*/?\s*(\d+\.?\d*)?', text, re.I)
        if gpa:
            data['gpa'] = gpa.group(1)
            if gpa.group(2):
                data['gpa_scale'] = gpa.group(2)
        else:
            issues.append('Could not detect GPA')

        uni = re.search(r'(?:university|college|institute|school)[:\s]*(?:of\s+)?([A-Za-z\s]+)', text, re.I)
        if uni:
            data['university'] = uni.group(1).strip()[:80]

        deg = re.search(r"(?:bachelor|master|b\.?sc|m\.?sc|b\.?a|m\.?a|b\.?tech|m\.?tech|phd|diploma)['\s]*(?:of|in)?\s*([A-Za-z\s]+)?", text, re.I)
        if deg:
            data['degree'] = deg.group(0).strip()[:80]

        quality = 80 if len(data) >= 2 else (55 if data else 30)
        summary = f"Academic transcript analysed. Detected: {', '.join(data.keys()) or 'none'}."
        if issues:
            summary += f" Issues: {'; '.join(issues)}."

        return {
            'summary': summary,
            'extracted_data': data,
            'doc_type_confirmed': 'transcript',
            'quality_score': quality,
            'issues': issues,
        }

    # --- English test -----------------------------------------------
    @staticmethod
    def _analyze_english_test(text: str) -> dict:
        data = {}
        issues = []

        if re.search(r'ielts', text, re.I):
            data['test_type'] = 'IELTS'
        elif re.search(r'toefl', text, re.I):
            data['test_type'] = 'TOEFL'
        else:
            issues.append('Could not determine test type (IELTS/TOEFL)')

        score = re.search(r'(?:overall band score|overall score|total score|band score|overall)[^\d]*(\d+\.?\d*)', text, re.I)
        if score:
            data['overall_score'] = score.group(1)
            s = float(data['overall_score'])
            if data.get('test_type') == 'IELTS' and s < 6.5:
                issues.append(f'IELTS score {s} is below typical requirement of 6.5')
            elif data.get('test_type') == 'TOEFL' and s < 80:
                issues.append(f'TOEFL score {s} is below typical requirement of 80')
        else:
            issues.append('Could not detect overall score')

        quality = 85 if len(data) >= 2 else (50 if data else 25)
        summary = f"English test score analysed. Detected: {', '.join(data.keys()) or 'none'}."
        if issues:
            summary += f" Issues: {'; '.join(issues)}."

        return {
            'summary': summary,
            'extracted_data': data,
            'doc_type_confirmed': 'english_test',
            'quality_score': quality,
            'issues': issues,
        }

    # --- SOP --------------------------------------------------------
    @staticmethod
    def _analyze_sop(text: str) -> dict:
        data = {}
        issues = []
        word_count = len(text.split())
        data['word_count'] = word_count

        if word_count < 100:
            issues.append('Document appears too short for a Statement of Purpose')

        keywords = ['motivation', 'career', 'goal', 'experience', 'research',
                     'passion', 'program', 'university', 'contribute', 'skill']
        found_kw = [k for k in keywords if k in text.lower()]
        data['key_themes'] = found_kw

        quality = min(90, 40 + len(found_kw) * 5 + min(word_count // 50, 20))
        summary = (f"Statement of Purpose analysed. Word count: {word_count}. "
                   f"Key themes: {', '.join(found_kw) or 'none detected'}.")
        if issues:
            summary += f" Issues: {'; '.join(issues)}."

        return {
            'summary': summary,
            'extracted_data': data,
            'doc_type_confirmed': 'sop',
            'quality_score': quality,
            'issues': issues,
        }

    # --- Resume -----------------------------------------------------
    @staticmethod
    def _analyze_resume(text: str) -> dict:
        data = {}
        issues = []

        email = re.search(r'[\w.+-]+@[\w-]+\.[\w.]+', text)
        if email:
            data['email'] = email.group()

        phone = re.search(r'[\+]?[\d\s\-\(\)]{7,15}', text)
        if phone:
            data['phone'] = phone.group().strip()

        skill_kw = ['python', 'java', 'javascript', 'react', 'sql', 'machine learning',
                     'data', 'communication', 'leadership', 'project management',
                     'c\\+\\+', 'node', 'flask', 'django', 'aws', 'docker']
        found_skills = [s for s in skill_kw if re.search(s, text, re.I)]
        data['skills'] = found_skills

        edu_kw = ['bachelor', 'master', 'phd', 'b.sc', 'm.sc', 'b.tech', 'm.tech',
                  'university', 'college', 'degree', 'diploma']
        found_edu = [e for e in edu_kw if re.search(e, text, re.I)]
        data['education_keywords'] = found_edu

        quality = min(90, 40 + len(found_skills) * 4 + len(found_edu) * 5)
        summary = (f"Resume analysed. Skills: {', '.join(found_skills) or 'none'}. "
                   f"Education: {', '.join(found_edu) or 'none'}.")
        if issues:
            summary += f" Issues: {'; '.join(issues)}."

        return {
            'summary': summary,
            'extracted_data': data,
            'doc_type_confirmed': 'resume',
            'quality_score': quality,
            'issues': issues,
        }

    # --- Recommendation letter --------------------------------------
    @staticmethod
    def _analyze_recommendation(text: str) -> dict:
        data = {}
        issues = []
        word_count = len(text.split())
        data['word_count'] = word_count

        if word_count < 80:
            issues.append('Recommendation letter appears too short')

        pos_words = ['excellent', 'outstanding', 'exceptional', 'dedicated',
                     'recommend', 'talented', 'strong', 'impressive', 'capable',
                     'remarkable', 'diligent', 'innovative']
        found = [w for w in pos_words if w in text.lower()]
        data['positive_descriptors'] = found
        data['recommendation_strength'] = (
            'strong' if len(found) >= 4 else 'moderate' if len(found) >= 2 else 'weak'
        )

        quality = min(90, 35 + len(found) * 6 + min(word_count // 40, 20))
        summary = (f"Recommendation letter analysed. Strength: {data['recommendation_strength']}. "
                   f"Positive descriptors: {', '.join(found) or 'none'}.")
        if issues:
            summary += f" Issues: {'; '.join(issues)}."

        return {
            'summary': summary,
            'extracted_data': data,
            'doc_type_confirmed': 'recommendation',
            'quality_score': quality,
            'issues': issues,
        }

    # --- Generic ----------------------------------------------------
    @staticmethod
    def _analyze_generic(text: str) -> dict:
        word_count = len(text.split())
        return {
            'summary': f"Document analysed. Word count: {word_count}.",
            'extracted_data': {'word_count': word_count},
            'doc_type_confirmed': 'unknown',
            'quality_score': 50,
            'issues': ['Document type could not be specifically analysed'],
        }
