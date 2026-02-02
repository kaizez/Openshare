"""
Machine Learning-based Authentication Security
Detects anomalous login behavior using behavioral analytics
"""

import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import json
from typing import Dict, Tuple, Optional

class LoginBehaviorAnalyzer:
    """
    ML-based login behavior analysis for anomaly detection
    Uses Isolation Forest for unsupervised anomaly detection
    """

    def __init__(self, model_path='models'):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.min_samples_for_training = 5  # Minimum logins before ML kicks in

        # Create models directory if it doesn't exist
        os.makedirs(model_path, exist_ok=True)

    def extract_features(self, login_data: Dict) -> np.array:
        """
        Extract features from login attempt for ML analysis

        Features:
        1. Hour of day (0-23)
        2. Day of week (0-6)
        3. Is weekend (0 or 1)
        4. Location changed (0 or 1)
        5. IP changed (0 or 1)
        6. Device changed (0 or 1)
        7. Time since last login (hours)
        8. Login frequency (logins per day)
        9. Failed attempts before this login
        10. Distance from usual location (0-10 scale)
        """

        now = datetime.utcnow()

        # Time-based features
        hour_of_day = now.hour
        day_of_week = now.weekday()
        is_weekend = 1 if day_of_week >= 5 else 0

        # Change detection features
        location_changed = 1 if login_data.get('location_changed', False) else 0
        ip_changed = 1 if login_data.get('ip_changed', False) else 0
        device_changed = 1 if login_data.get('device_changed', False) else 0

        # Behavioral features
        hours_since_last_login = login_data.get('hours_since_last_login', 24)
        logins_per_day = login_data.get('logins_per_day', 1)
        failed_attempts = login_data.get('failed_attempts', 0)

        # Location distance (normalized 0-10)
        location_distance = login_data.get('location_distance', 0)

        features = np.array([
            hour_of_day,
            day_of_week,
            is_weekend,
            location_changed,
            ip_changed,
            device_changed,
            hours_since_last_login,
            logins_per_day,
            failed_attempts,
            location_distance
        ]).reshape(1, -1)

        return features

    def calculate_risk_score(self, login_data: Dict, user_login_history: list) -> Tuple[float, str, list]:
        """
        Calculate risk score for a login attempt

        Returns:
            Tuple of (risk_score, risk_level, risk_factors)
            - risk_score: 0-100 (0=safe, 100=very suspicious)
            - risk_level: 'low', 'medium', 'high', 'critical'
            - risk_factors: List of detected risk factors
        """

        risk_score = 0.0
        risk_factors = []

        # Rule-based risk factors (always active, even without ML)

        # 1. Impossible Travel Detection
        if login_data.get('impossible_travel', False):
            risk_score += 40
            risk_factors.append('Impossible travel detected')

        # 2. New Device
        if login_data.get('device_changed', False):
            risk_score += 15
            risk_factors.append('Login from new device')

        # 3. New Location
        if login_data.get('location_changed', False):
            risk_score += 10
            risk_factors.append('Login from new location')

        # 4. Unusual Time
        hour = datetime.utcnow().hour
        if hour >= 2 and hour <= 5:  # 2 AM - 5 AM unusual
            risk_score += 10
            risk_factors.append('Unusual time of day (2 AM - 5 AM)')

        # 5. Recent Failed Attempts
        failed_attempts = login_data.get('failed_attempts', 0)
        if failed_attempts > 0:
            risk_score += min(failed_attempts * 5, 20)
            risk_factors.append(f'{failed_attempts} recent failed login attempts')

        # 6. IP Address Change
        if login_data.get('ip_changed', False):
            risk_score += 10
            risk_factors.append('IP address changed')

        # 7. High Login Frequency (potential bot)
        logins_today = login_data.get('logins_today', 0)
        if logins_today > 10:
            risk_score += 15
            risk_factors.append(f'High login frequency ({logins_today} logins today)')

        # 8. VPN/Proxy Detection (if location distance is very high)
        location_distance = login_data.get('location_distance', 0)
        if location_distance > 8:
            risk_score += 10
            risk_factors.append('Potential VPN/Proxy usage')

        # ML-based anomaly detection (if enough data)
        if len(user_login_history) >= self.min_samples_for_training:
            try:
                # Extract features from current login
                current_features = self.extract_features(login_data)

                # Extract features from historical logins
                historical_features = []
                for historical_login in user_login_history:
                    features = self.extract_features(historical_login)
                    historical_features.append(features.flatten())

                historical_features = np.array(historical_features)

                # Train/update model on user's historical behavior
                model = IsolationForest(contamination=0.1, random_state=42)
                model.fit(historical_features)

                # Predict if current login is anomalous
                prediction = model.predict(current_features)
                anomaly_score = model.score_samples(current_features)[0]

                if prediction[0] == -1:  # Anomaly detected
                    ml_risk = abs(anomaly_score) * 30  # Scale to 0-30
                    risk_score += ml_risk
                    risk_factors.append(f'ML anomaly detected (score: {anomaly_score:.2f})')

            except Exception as e:
                # ML failed, continue with rule-based scoring
                print(f"ML anomaly detection error: {e}")

        # Cap risk score at 100
        risk_score = min(risk_score, 100)

        # Determine risk level
        if risk_score < 20:
            risk_level = 'low'
        elif risk_score < 40:
            risk_level = 'medium'
        elif risk_score < 70:
            risk_level = 'high'
        else:
            risk_level = 'critical'

        return risk_score, risk_level, risk_factors

    def check_impossible_travel(self, last_location: str, current_location: str,
                                time_diff_hours: float) -> bool:
        """
        Detect impossible travel - logging in from two distant locations in short time

        Simplified version: checks if location changed in less than 1 hour
        (Real version would calculate actual distance and speed)
        """

        if not last_location or not current_location:
            return False

        if last_location == current_location:
            return False

        # If location changed in less than 1 hour, flag as impossible travel
        # (Real implementation would use actual distance calculation)
        if time_diff_hours < 1.0:
            return True

        return False

    def should_require_additional_verification(self, risk_level: str) -> bool:
        """
        Determine if additional verification is needed based on risk level

        - low: No additional verification
        - medium: Recommend MFA (if not enabled)
        - high: Require email verification code
        - critical: Require email verification + manual review
        """

        return risk_level in ['high', 'critical']

    def get_security_action(self, risk_score: float, risk_level: str) -> Dict:
        """
        Determine what security action to take based on risk

        Returns dict with:
        - action: 'allow', 'verify_email', 'verify_mfa', 'block'
        - message: User-friendly message
        - log_level: 'info', 'warning', 'critical'
        """

        if risk_level == 'low':
            return {
                'action': 'allow',
                'message': 'Login allowed',
                'log_level': 'info'
            }

        elif risk_level == 'medium':
            return {
                'action': 'verify_mfa',
                'message': 'Unusual login detected. Please verify with MFA.',
                'log_level': 'warning'
            }

        elif risk_level == 'high':
            return {
                'action': 'verify_email',
                'message': 'Suspicious login detected. Verification code sent to your email.',
                'log_level': 'warning'
            }

        else:  # critical
            return {
                'action': 'block',
                'message': 'Login blocked due to high risk. Please contact support.',
                'log_level': 'critical'
            }


def build_login_data(user, current_ip, current_location, device_fingerprint,
                     login_history) -> Dict:
    """
    Build login data dictionary for ML analysis

    Args:
        user: User model object
        current_ip: Current IP address
        current_location: Current location string
        device_fingerprint: Device fingerprint hash
        login_history: List of recent login records

    Returns:
        Dictionary with login data for analysis
    """

    # Calculate time-based metrics
    now = datetime.utcnow()

    if user.last_login_ip and login_history:
        # Get most recent login
        last_login = login_history[0] if login_history else {}
        last_login_time = last_login.get('timestamp', now - timedelta(days=1))

        time_diff = now - last_login_time
        hours_since_last_login = time_diff.total_seconds() / 3600

        # Count logins in last 24 hours
        logins_today = sum(
            1 for login in login_history
            if (now - login.get('timestamp', now)).total_seconds() < 86400
        )

        # Count logins in last 7 days for frequency
        logins_this_week = sum(
            1 for login in login_history
            if (now - login.get('timestamp', now)).total_seconds() < 604800
        )
        logins_per_day = logins_this_week / 7.0

    else:
        hours_since_last_login = 24
        logins_today = 0
        logins_per_day = 1

    # Detect changes
    ip_changed = user.last_login_ip != current_ip if user.last_login_ip else False
    location_changed = user.last_login_location != current_location if user.last_login_location else False

    # Device change detection (simplified - would need device tracking in DB)
    device_changed = False  # Would check against stored device fingerprints

    # Calculate location distance (simplified 0-10 scale)
    # Real implementation would use actual geographic distance
    if location_changed:
        location_distance = 5  # Medium distance
    else:
        location_distance = 0

    # Impossible travel check
    impossible_travel = False
    if location_changed and hours_since_last_login < 1.0:
        impossible_travel = True
        location_distance = 10  # Maximum distance

    return {
        'timestamp': now,
        'ip': current_ip,
        'location': current_location,
        'device_fingerprint': device_fingerprint,
        'hour_of_day': now.hour,
        'day_of_week': now.weekday(),
        'is_weekend': now.weekday() >= 5,
        'location_changed': location_changed,
        'ip_changed': ip_changed,
        'device_changed': device_changed,
        'hours_since_last_login': hours_since_last_login,
        'logins_per_day': logins_per_day,
        'logins_today': logins_today,
        'failed_attempts': user.failed_login_attempts or 0,
        'location_distance': location_distance,
        'impossible_travel': impossible_travel
    }
