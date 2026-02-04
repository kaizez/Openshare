"""
Keystroke Dynamics Authentication
Analyzes typing patterns as a biometric identifier
"""

import json
import numpy as np
from typing import Dict, List, Tuple, Optional

class KeystrokeDynamics:
    """
    Analyzes keystroke timing patterns for user authentication.

    Captures:
    - Hold time: How long each key is pressed
    - Flight time: Time between releasing one key and pressing next
    - Digraph latency: Time between pressing two consecutive keys
    """

    # Similarity threshold (0-1, lower = stricter)
    SIMILARITY_THRESHOLD = 0.65
    MIN_SAMPLES = 3  # Minimum login samples before enforcing

    def __init__(self):
        pass

    def extract_features(self, keystroke_data: List[Dict]) -> Dict:
        """
        Extract features from raw keystroke data.

        keystroke_data format:
        [
            {"key": "a", "press": 1000, "release": 1050},
            {"key": "b", "press": 1080, "release": 1130},
            ...
        ]

        Returns feature dict with hold times and flight times.
        """
        if not keystroke_data or len(keystroke_data) < 2:
            return None

        hold_times = []
        flight_times = []
        digraph_times = []

        for i, ks in enumerate(keystroke_data):
            # Hold time = release - press
            hold = ks.get('release', 0) - ks.get('press', 0)
            if hold > 0 and hold < 1000:  # Filter outliers
                hold_times.append(hold)

            # Flight time = next_press - current_release
            if i < len(keystroke_data) - 1:
                next_ks = keystroke_data[i + 1]
                flight = next_ks.get('press', 0) - ks.get('release', 0)
                if flight > -500 and flight < 1000:  # Allow some overlap
                    flight_times.append(flight)

                # Digraph = next_press - current_press
                digraph = next_ks.get('press', 0) - ks.get('press', 0)
                if digraph > 0 and digraph < 1500:
                    digraph_times.append(digraph)

        if not hold_times or not flight_times:
            return None

        return {
            'hold_mean': np.mean(hold_times),
            'hold_std': np.std(hold_times) if len(hold_times) > 1 else 0,
            'flight_mean': np.mean(flight_times),
            'flight_std': np.std(flight_times) if len(flight_times) > 1 else 0,
            'digraph_mean': np.mean(digraph_times) if digraph_times else 0,
            'digraph_std': np.std(digraph_times) if len(digraph_times) > 1 else 0,
            'total_time': keystroke_data[-1].get('release', 0) - keystroke_data[0].get('press', 0),
            'num_keys': len(keystroke_data)
        }

    def calculate_similarity(self, profile: Dict, current: Dict) -> float:
        """
        Calculate similarity between stored profile and current typing.
        Returns value 0-1 (1 = identical).
        """
        if not profile or not current:
            return 0.0

        # Features to compare with weights
        features = [
            ('hold_mean', 0.25),
            ('hold_std', 0.10),
            ('flight_mean', 0.25),
            ('flight_std', 0.10),
            ('digraph_mean', 0.20),
            ('digraph_std', 0.10)
        ]

        total_similarity = 0.0
        total_weight = 0.0

        for feature, weight in features:
            profile_val = profile.get(feature, 0)
            current_val = current.get(feature, 0)

            if profile_val == 0 and current_val == 0:
                similarity = 1.0
            elif profile_val == 0 or current_val == 0:
                similarity = 0.5
            else:
                # Calculate percentage difference
                diff = abs(profile_val - current_val) / max(profile_val, current_val)
                similarity = max(0, 1 - diff)

            total_similarity += similarity * weight
            total_weight += weight

        return total_similarity / total_weight if total_weight > 0 else 0.0

    def update_profile(self, existing_profile: Optional[Dict], new_features: Dict) -> Dict:
        """
        Update user's keystroke profile with new sample.
        Uses exponential moving average for adaptation.
        """
        if not existing_profile:
            return {
                'samples': 1,
                'hold_mean': new_features['hold_mean'],
                'hold_std': new_features['hold_std'],
                'flight_mean': new_features['flight_mean'],
                'flight_std': new_features['flight_std'],
                'digraph_mean': new_features['digraph_mean'],
                'digraph_std': new_features['digraph_std']
            }

        # Exponential moving average (alpha = 0.3 for recent bias)
        alpha = 0.3
        samples = existing_profile.get('samples', 1)

        updated = {
            'samples': samples + 1,
            'hold_mean': (1 - alpha) * existing_profile['hold_mean'] + alpha * new_features['hold_mean'],
            'hold_std': (1 - alpha) * existing_profile['hold_std'] + alpha * new_features['hold_std'],
            'flight_mean': (1 - alpha) * existing_profile['flight_mean'] + alpha * new_features['flight_mean'],
            'flight_std': (1 - alpha) * existing_profile['flight_std'] + alpha * new_features['flight_std'],
            'digraph_mean': (1 - alpha) * existing_profile['digraph_mean'] + alpha * new_features['digraph_mean'],
            'digraph_std': (1 - alpha) * existing_profile['digraph_std'] + alpha * new_features['digraph_std']
        }

        return updated

    def verify(self, user_profile_json: Optional[str], keystroke_data: List[Dict]) -> Tuple[bool, float, str]:
        """
        Verify user based on keystroke dynamics.

        Returns:
            (is_valid, similarity_score, message)
        """
        # Extract features from current typing
        current_features = self.extract_features(keystroke_data)

        if not current_features:
            return True, 0.0, "Insufficient keystroke data"

        # No profile yet - accept and will build profile
        if not user_profile_json:
            return True, 1.0, "No profile yet - building"

        try:
            profile = json.loads(user_profile_json)
        except:
            return True, 1.0, "Invalid profile - rebuilding"

        # Not enough samples yet - accept but flag
        if profile.get('samples', 0) < self.MIN_SAMPLES:
            return True, 1.0, f"Building profile ({profile.get('samples', 0)}/{self.MIN_SAMPLES})"

        # Calculate similarity
        similarity = self.calculate_similarity(profile, current_features)

        if similarity >= self.SIMILARITY_THRESHOLD:
            return True, similarity, f"Keystroke match ({similarity:.1%})"
        else:
            return False, similarity, f"Keystroke mismatch ({similarity:.1%})"


# Global instance
keystroke_analyzer = KeystrokeDynamics()
