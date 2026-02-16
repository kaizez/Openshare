"""
ML-backed file trust score analyzer.

Pipeline:
  file_bytes + filename + detected_mime
      -> extract_features()       (8 numeric/boolean features)
      -> compute_trust_score()    (heuristic deductions + IsolationForest)
      -> analyze_file()           (top-level entry point, stores nothing itself)
"""

import math
import re
import hashlib
from datetime import datetime

# Module-level IsolationForest cache
_model = None
_model_trained_on = 0  # number of samples the current model was trained on

DANGEROUS_EXTENSIONS = {'.exe', '.bat', '.ps1', '.vbs', '.cmd', '.scr', '.com', '.pif', '.msi', '.jar'}

# Patterns considered suspicious when found inside documents/PDFs
_SUSPICIOUS_PATTERNS = [
    rb'(?i)invoke-expression',
    rb'(?i)iex\s*\(',
    rb'(?i)downloadstring',
    rb'(?i)frombase64string',
    rb'(?i)powershell\s+-',
    rb'(?i)<script[\s>]',
    rb'(?i)eval\s*\(',
    rb'(?i)cmd\.exe',
    rb'(?i)wscript',
    rb'(?i)mshta',
    rb'[A-Za-z0-9+/]{60,}={0,2}',  # base64 blobs ≥60 chars
]

_COMPILED_PATTERNS = [re.compile(p) for p in _SUSPICIOUS_PATTERNS]


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of byte sequence (0–8 bits)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def _is_text_extension(ext: str) -> bool:
    return ext.lower() in {
        '.txt', '.csv', '.log', '.xml', '.json', '.html', '.htm',
        '.yaml', '.yml', '.ini', '.cfg', '.conf', '.md', '.rst',
        '.py', '.js', '.ts', '.css', '.sql', '.sh', '.rb', '.go',
    }


def extract_features(file_bytes: bytes, filename: str, detected_mime: str) -> dict:
    """Extract 8 numeric/boolean features from a file."""
    import os
    ext = os.path.splitext(filename.lower())[1] if filename else ''

    # 1. Entropy
    entropy = _shannon_entropy(file_bytes)

    # 2. MIME mismatch
    declared_is_text = _is_text_extension(ext)
    detected_is_text = (detected_mime or '').startswith('text/')
    # Only flag mismatch when they clearly disagree
    if detected_mime and ext:
        # extension claims text but detected as binary
        mime_mismatch = int(declared_is_text and not detected_is_text and
                            not (detected_mime or '').startswith('application/json') and
                            not (detected_mime or '').startswith('application/xml'))
        # extension claims binary executable but detected as text is also odd
        if ext in DANGEROUS_EXTENSIONS and detected_is_text:
            mime_mismatch = 1
    else:
        mime_mismatch = 0

    # 3. Dangerous extension
    dangerous_extension = int(ext in DANGEROUS_EXTENSIONS)

    # 4. PE header in non-executable
    pe_in_non_exe = int(
        file_bytes[:2] == b'\x4d\x5a' and ext not in {'.exe', '.dll', '.sys', '.scr', '.com'}
    )

    # 5. Null byte ratio
    total = len(file_bytes)
    null_count = file_bytes.count(b'\x00') if total > 0 else 0
    null_byte_ratio = null_count / total if total > 0 else 0.0

    # 6. Printable ratio
    printable_count = sum(1 for b in file_bytes if 32 <= b <= 126 or b in (9, 10, 13))
    printable_ratio = printable_count / total if total > 0 else 0.0

    # 7. Suspicious pattern count
    suspicious_pattern_count = sum(
        1 for pat in _COMPILED_PATTERNS if pat.search(file_bytes)
    )

    # 8. Anomaly score placeholder — filled in by compute_trust_score() after IF runs
    anomaly_score = 0.0

    return {
        'entropy': round(entropy, 4),
        'mime_mismatch': mime_mismatch,
        'dangerous_extension': dangerous_extension,
        'pe_in_non_exe': pe_in_non_exe,
        'null_byte_ratio': round(null_byte_ratio, 4),
        'printable_ratio': round(printable_ratio, 4),
        'suspicious_pattern_count': suspicious_pattern_count,
        'anomaly_score': anomaly_score,
        '_ext': ext,
        '_detected_mime': detected_mime or '',
    }


# ---------------------------------------------------------------------------
# IsolationForest helpers
# ---------------------------------------------------------------------------

def _feature_vector(features: dict) -> list:
    """Convert a features dict into a flat numeric list for sklearn."""
    return [
        features.get('entropy', 0.0),
        float(features.get('mime_mismatch', 0)),
        float(features.get('dangerous_extension', 0)),
        float(features.get('pe_in_non_exe', 0)),
        features.get('null_byte_ratio', 0.0),
        features.get('printable_ratio', 0.0),
        float(features.get('suspicious_pattern_count', 0)),
        features.get('anomaly_score', 0.0),
    ]


def _get_or_train_model(feature_rows: list):
    """
    Return a trained IsolationForest (or None if too few samples).
    Retrains when the sample count has grown by ≥10 since last training,
    or on the first call with ≥5 samples.
    """
    global _model, _model_trained_on

    count = len(feature_rows)
    if count < 5:
        return None

    if _model is not None and count - _model_trained_on < 10:
        return _model

    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest

        X = np.array([_feature_vector(r) for r in feature_rows], dtype=float)
        clf = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
        clf.fit(X)
        _model = clf
        _model_trained_on = count
        print(f'[ML] IsolationForest trained on {count} samples', flush=True)
        return _model
    except Exception as e:
        print(f'[ML] IsolationForest training failed: {e}', flush=True)
        return None


# ---------------------------------------------------------------------------
# Trust score computation
# ---------------------------------------------------------------------------

def compute_trust_score(features: dict, model=None) -> tuple:
    """
    Compute (trust_score: int, risk_level: str, risk_signals: list[dict]).

    Starts at 100 and deducts points for each risk signal.
    Clamps result to [0, 100].
    """
    score = 100
    risk_signals = []
    ext = features.get('_ext', '')
    detected_mime = features.get('_detected_mime', '')
    is_text_ext = _is_text_extension(ext)

    # --- Entropy ---
    entropy = features.get('entropy', 0.0)
    if entropy > 7.5:
        score -= 25
        risk_signals.append({
            'name': 'high_entropy',
            'description': f'Extremely high byte entropy ({entropy:.2f}) — typical of encrypted or packed content',
            'severity': 'high',
            'deduction': 25,
        })
    elif entropy > 7.0:
        score -= 10
        risk_signals.append({
            'name': 'elevated_entropy',
            'description': f'Elevated byte entropy ({entropy:.2f}) — possible compression or obfuscation',
            'severity': 'medium',
            'deduction': 10,
        })

    # --- MIME mismatch ---
    if features.get('mime_mismatch', 0):
        score -= 30
        risk_signals.append({
            'name': 'mime_mismatch',
            'description': f'Declared extension ({ext or "none"}) does not match detected MIME type ({detected_mime or "unknown"})',
            'severity': 'high',
            'deduction': 30,
        })

    # --- Dangerous extension ---
    if features.get('dangerous_extension', 0):
        score -= 20
        risk_signals.append({
            'name': 'dangerous_extension',
            'description': f'File uses a potentially dangerous extension ({ext})',
            'severity': 'medium',
            'deduction': 20,
        })

    # --- PE header in non-executable ---
    if features.get('pe_in_non_exe', 0):
        score -= 35
        risk_signals.append({
            'name': 'pe_in_non_exe',
            'description': 'Windows PE/MZ executable header found in a non-executable file — likely embedded malware',
            'severity': 'critical',
            'deduction': 35,
        })

    # --- Null byte ratio (only flags text-declared files) ---
    null_ratio = features.get('null_byte_ratio', 0.0)
    if null_ratio > 0.1 and is_text_ext:
        score -= 20
        risk_signals.append({
            'name': 'null_bytes_in_text',
            'description': f'High null-byte ratio ({null_ratio:.1%}) in a text file — possible binary masquerading as text',
            'severity': 'medium',
            'deduction': 20,
        })

    # --- Low printable ratio (only flags text-declared files) ---
    printable = features.get('printable_ratio', 1.0)
    if printable < 0.3 and is_text_ext:
        score -= 10
        risk_signals.append({
            'name': 'low_printable_ratio',
            'description': f'Low printable character ratio ({printable:.1%}) for a text file',
            'severity': 'low',
            'deduction': 10,
        })

    # --- Suspicious patterns ---
    pattern_count = features.get('suspicious_pattern_count', 0)
    if pattern_count >= 3:
        score -= 25
        risk_signals.append({
            'name': 'many_suspicious_patterns',
            'description': f'{pattern_count} suspicious patterns found (PowerShell, base64, scripts)',
            'severity': 'high',
            'deduction': 25,
        })
    elif pattern_count >= 1:
        score -= 15
        risk_signals.append({
            'name': 'suspicious_patterns',
            'description': f'{pattern_count} suspicious pattern(s) found (PowerShell, base64, scripts)',
            'severity': 'medium',
            'deduction': 15,
        })

    # --- IsolationForest anomaly score ---
    anomaly_score = features.get('anomaly_score', 0.0)
    if anomaly_score < -0.1:
        score -= 15
        risk_signals.append({
            'name': 'anomaly_detected',
            'description': f'ML anomaly detector flagged this file as unusual (score {anomaly_score:.3f})',
            'severity': 'medium',
            'deduction': 15,
        })

    score = max(0, min(100, score))

    if score >= 80:
        risk_level = 'trustworthy'
    elif score >= 60:
        risk_level = 'caution'
    elif score >= 40:
        risk_level = 'suspicious'
    else:
        risk_level = 'high_risk'

    return score, risk_level, risk_signals


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def analyze_file(file_bytes: bytes, filename: str, detected_mime: str, db) -> dict:
    """
    Full analysis pipeline.  Returns a dict ready to unpack into
    db.store_ml_analysis(**result).

    `db` is a FileTransfer Database instance (passed from the upload route
    to avoid circular imports).
    """
    import os

    features = extract_features(file_bytes, filename, detected_mime)

    # Load existing feature vectors for IsolationForest training
    model = None
    anomaly_score_val = 0.0
    try:
        existing_rows = db.get_all_ml_features()
        # Build feature-list rows for training
        feature_rows = [r.get('features', {}) for r in existing_rows if r.get('features')]
        model = _get_or_train_model(feature_rows)
        if model is not None:
            import numpy as np
            vec = _feature_vector(features)
            anomaly_score_val = float(model.decision_function([vec])[0])
            features['anomaly_score'] = round(anomaly_score_val, 4)
    except Exception as e:
        print(f'[ML] Anomaly scoring failed: {e}', flush=True)

    trust_score, risk_level, risk_signals = compute_trust_score(features, model)

    # Remove internal-only keys before storing
    stored_features = {k: v for k, v in features.items() if not k.startswith('_')}

    # Derive file_id from filename — the caller passes file_id separately;
    # but analyze_file() doesn't know it.  We return a dict without file_id
    # and let the caller supply it.
    return {
        'trust_score': trust_score,
        'risk_level': risk_level,
        'risk_signals': risk_signals,
        'features': stored_features,
        'anomaly_score': round(anomaly_score_val, 4),
    }
