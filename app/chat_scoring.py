"""
Chat Scoring Module - ML-based toxicity, vulgarity and sensitive data detection for OpenShare chatbot.
Uses keyword matching with weighted scoring and regex pattern detection.
"""

import re
import json
import os
from collections import defaultdict

# --- Sensitive Information Patterns (regex-based) ---
SENSITIVE_PATTERNS = {
    # Financial
    'credit_card': {
        'pattern': r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
        'score': 0.85,
        'label': 'Credit Card Number',
        'category': 'financial'
    },
    'bank_account': {
        'pattern': r'\b\d{3}[\s\-]?\d{5}[\s\-]?\d{3}\b',
        'score': 0.8,
        'label': 'Bank Account Number',
        'category': 'financial'
    },
    'cvv': {
        'pattern': r'\b(?:cvv|cvc|csv|cvn)[\s:]*\d{3,4}\b',
        'score': 0.85,
        'label': 'CVV Code',
        'category': 'financial'
    },

    # Personal Identity
    'nric': {
        'pattern': r'\b[STFGMstfgm]\d{7}[A-Za-z]\b',
        'score': 0.9,
        'label': 'Singapore NRIC',
        'category': 'identity'
    },
    'passport': {
        'pattern': r'\b(?:passport)[\s:#]*[A-Z0-9]{6,9}\b',
        'score': 0.85,
        'label': 'Passport Number',
        'category': 'identity'
    },
    'ssn': {
        'pattern': r'\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b',
        'score': 0.9,
        'label': 'SSN',
        'category': 'identity'
    },
    'phone_number': {
        'pattern': r'\b(?:\+65[\s\-]?)?[689]\d{3}[\s\-]?\d{4}\b',
        'score': 0.5,
        'label': 'Phone Number',
        'category': 'identity'
    },
    'email_address': {
        'pattern': r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b',
        'score': 0.4,
        'label': 'Email Address',
        'category': 'identity'
    },

    # Credentials & Secrets
    'password_share': {
        'pattern': r'(?i)\b(?:password|passwd|pwd)[\s:=]+\S{4,}',
        'score': 0.95,
        'label': 'Password',
        'category': 'credentials'
    },
    'api_key': {
        'pattern': r'(?i)\b(?:api[_\-\s]?key|apikey|token|secret[_\-\s]?key|auth[_\-\s]?token)[\s:=]+\S{8,}',
        'score': 0.9,
        'label': 'API Key / Token',
        'category': 'credentials'
    },
    'private_key': {
        'pattern': r'(?i)-----\s*BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY',
        'score': 1.0,
        'label': 'Private Key',
        'category': 'credentials'
    },
    'connection_string': {
        'pattern': r'(?i)(?:mysql|postgres|mongodb|redis|sqlite|mssql)://\S+',
        'score': 0.95,
        'label': 'Database Connection String',
        'category': 'credentials'
    },
    'aws_key': {
        'pattern': r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
        'score': 0.95,
        'label': 'AWS Access Key',
        'category': 'credentials'
    },

    # File Paths & System Info
    'file_path_linux': {
        'pattern': r'(?:^|\s)/(?:etc|var|home|root|usr|opt|tmp)/\S+',
        'score': 0.6,
        'label': 'Linux File Path',
        'category': 'system'
    },
    'file_path_windows': {
        'pattern': r'(?i)[A-Z]:\\(?:Users|Windows|Program Files|AppData)\\\S+',
        'score': 0.6,
        'label': 'Windows File Path',
        'category': 'system'
    },
    'ip_address_private': {
        'pattern': r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
        'score': 0.55,
        'label': 'Private IP Address',
        'category': 'system'
    },

    # Security Probing
    'sql_injection': {
        'pattern': r"(?i)(?:'\s*(?:OR|AND)\s+['\d]|UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+\w+\s+SET)",
        'score': 0.95,
        'label': 'SQL Injection Attempt',
        'category': 'attack'
    },
    'xss_attempt': {
        'pattern': r'(?i)<\s*script[\s>]|javascript\s*:|on(?:error|load|click)\s*=',
        'score': 0.9,
        'label': 'XSS Attempt',
        'category': 'attack'
    },
    'command_injection': {
        'pattern': r'(?:;\s*(?:cat|rm|wget|curl|bash|sh|nc|ncat)\s|&&\s*(?:cat|rm|wget|curl)\s|\|\s*(?:bash|sh)\b)',
        'score': 0.9,
        'label': 'Command Injection Attempt',
        'category': 'attack'
    },
}

# Vulgarity/toxicity word lists with severity weights (0.0 - 1.0)
VULGARITY_PATTERNS = {
    # High severity (0.8 - 1.0)
    'fuck': 0.9, 'f*ck': 0.9, 'fck': 0.9, 'fuk': 0.9, 'fuq': 0.9,
    'shit': 0.8, 'sh1t': 0.8, 'sht': 0.8,
    'bitch': 0.85, 'b1tch': 0.85, 'btch': 0.85,
    'asshole': 0.85, 'a$$hole': 0.85,
    'bastard': 0.8, 'b@stard': 0.8,
    'dick': 0.7, 'd1ck': 0.7,
    'pussy': 0.8, 'puss': 0.6,
    'cock': 0.7, 'c0ck': 0.7,
    'cunt': 0.95, 'c*nt': 0.95,
    'whore': 0.9, 'wh0re': 0.9,
    'slut': 0.85,
    'nigger': 1.0, 'n1gger': 1.0, 'nigga': 0.9, 'n1gga': 0.9,
    'faggot': 0.95, 'fag': 0.8, 'f@g': 0.8,
    'retard': 0.85, 'retarded': 0.85,

    # Medium severity (0.4 - 0.7)
    'damn': 0.4, 'dammit': 0.45,
    'hell': 0.3, 'crap': 0.35,
    'ass': 0.5, 'arse': 0.5,
    'stupid': 0.4, 'idiot': 0.45, 'moron': 0.45,
    'dumb': 0.35, 'loser': 0.4,
    'stfu': 0.7, 'gtfo': 0.7, 'lmao': 0.1,
    'wtf': 0.5, 'wth': 0.3,
    'piss': 0.5, 'pissed': 0.45,
    'bloody': 0.3, 'bugger': 0.4,

    # Threat/harassment patterns (high severity)
    'kill you': 0.95, 'kill yourself': 1.0, 'kys': 1.0,
    'die': 0.6, 'go die': 0.95,
    'hate you': 0.7, 'i hate': 0.5,
    'threat': 0.6, 'bomb': 0.7,
}

# Leet speak / obfuscation mapping
LEET_MAP = {
    '@': 'a', '4': 'a', '3': 'e', '1': 'i', '0': 'o',
    '$': 's', '5': 's', '7': 't', '+': 't',
}


def _normalize_text(text):
    """Normalize text by converting leet speak and removing special chars."""
    text = text.lower().strip()
    # Replace leet speak characters
    normalized = ''
    for char in text:
        normalized += LEET_MAP.get(char, char)
    # Remove repeated characters (e.g., "fuuuck" -> "fuck")
    normalized = re.sub(r'(.)\1{2,}', r'\1\1', normalized)
    return normalized


def _check_word_boundaries(text, pattern):
    """Check if pattern exists as a word or substring in text."""
    # Try exact word boundary match first
    regex = r'\b' + re.escape(pattern) + r'\b'
    if re.search(regex, text):
        return True
    # For short patterns (<=3 chars), require word boundary
    if len(pattern) <= 3:
        return False
    # For longer patterns, also check substring
    return pattern in text


def score_message(message):
    """
    Score a message for toxicity/vulgarity AND sensitive information leakage.

    Returns:
        dict: {
            'score': float (0.0 - 1.0),
            'flagged_words': list of matched vulgarity words,
            'sensitive_matches': list of dicts with label, category, matched text,
            'severity': str ('clean', 'mild', 'moderate', 'severe'),
            'categories': list of triggered categories (e.g. ['vulgarity', 'credentials', 'identity']),
            'should_warn': bool
        }
    """
    if not message:
        return {
            'score': 0.0,
            'flagged_words': [],
            'sensitive_matches': [],
            'severity': 'clean',
            'categories': [],
            'should_warn': False
        }

    normalized = _normalize_text(message)
    original_lower = message.lower().strip()
    categories = set()

    # --- Vulgarity detection ---
    flagged_words = []
    vulgarity_max = 0.0
    vulgarity_count = 0

    for pattern, weight in VULGARITY_PATTERNS.items():
        if _check_word_boundaries(normalized, pattern) or _check_word_boundaries(original_lower, pattern):
            flagged_words.append(pattern)
            vulgarity_max = max(vulgarity_max, weight)
            vulgarity_count += 1

    if vulgarity_count > 0:
        categories.add('vulgarity')

    # Calculate vulgarity score
    if vulgarity_count == 0:
        vulgarity_score = 0.0
    elif vulgarity_count == 1:
        vulgarity_score = vulgarity_max
    else:
        density_bonus = min(0.15 * (vulgarity_count - 1), 0.3)
        vulgarity_score = min(1.0, vulgarity_max + density_bonus)

    # --- Sensitive information detection ---
    sensitive_matches = []
    sensitive_max = 0.0

    for key, config in SENSITIVE_PATTERNS.items():
        match = re.search(config['pattern'], message)
        if match:
            sensitive_matches.append({
                'type': key,
                'label': config['label'],
                'category': config['category'],
                'matched': match.group(0)[:30] + ('...' if len(match.group(0)) > 30 else ''),
            })
            sensitive_max = max(sensitive_max, config['score'])
            categories.add(config['category'])

    # Calculate sensitive score
    if len(sensitive_matches) == 0:
        sensitive_score = 0.0
    elif len(sensitive_matches) == 1:
        sensitive_score = sensitive_max
    else:
        density_bonus = min(0.1 * (len(sensitive_matches) - 1), 0.2)
        sensitive_score = min(1.0, sensitive_max + density_bonus)

    # --- Combined final score: take the higher of the two ---
    final_score = round(max(vulgarity_score, sensitive_score), 2)

    # Determine severity level
    if final_score == 0:
        severity = 'clean'
    elif final_score < 0.4:
        severity = 'mild'
    elif final_score < 0.7:
        severity = 'moderate'
    else:
        severity = 'severe'

    # Warn if moderate or above
    should_warn = final_score >= 0.5

    return {
        'score': final_score,
        'flagged_words': flagged_words,
        'sensitive_matches': sensitive_matches,
        'severity': severity,
        'categories': list(categories),
        'should_warn': should_warn
    }


def get_user_behavior_score(chat_records):
    """
    Calculate a user's overall behavior score from their chat history.

    Args:
        chat_records: list of ChatHistory records for a user

    Returns:
        dict: {
            'behavior_score': float (0-100, higher = better),
            'total_messages': int,
            'flagged_count': int,
            'vulgar_count': int,
            'avg_toxicity': float,
            'warnings_issued': int,
            'risk_level': str ('good', 'caution', 'warning', 'critical')
        }
    """
    if not chat_records:
        return {
            'behavior_score': 100.0,
            'total_messages': 0,
            'flagged_count': 0,
            'vulgar_count': 0,
            'avg_toxicity': 0.0,
            'warnings_issued': 0,
            'risk_level': 'good'
        }

    total = len(chat_records)
    flagged_count = sum(1 for r in chat_records if r.flagged)
    vulgar_count = sum(1 for r in chat_records if (r.toxicity_score or 0) >= 0.5)
    total_toxicity = sum(r.toxicity_score or 0 for r in chat_records)
    avg_toxicity = round(total_toxicity / total, 3) if total > 0 else 0
    warnings_issued = sum(1 for r in chat_records if r.warning_issued)

    # Behavior score: start at 100, deduct for bad behavior
    score = 100.0
    if total > 0:
        # Deduct for flagged messages (sensitive content)
        score -= (flagged_count / total) * 20
        # Deduct for vulgar messages
        score -= (vulgar_count / total) * 40
        # Deduct for average toxicity
        score -= avg_toxicity * 30
        # Deduct for warnings
        score -= warnings_issued * 2

    score = round(max(0, min(100, score)), 1)

    # Determine risk level
    if score >= 80:
        risk_level = 'good'
    elif score >= 60:
        risk_level = 'caution'
    elif score >= 40:
        risk_level = 'warning'
    else:
        risk_level = 'critical'

    return {
        'behavior_score': score,
        'total_messages': total,
        'flagged_count': flagged_count,
        'vulgar_count': vulgar_count,
        'avg_toxicity': avg_toxicity,
        'warnings_issued': warnings_issued,
        'risk_level': risk_level
    }
