"""
Keystroke Dynamics Authentication with Autoencoder-Based Anomaly Detection

Analyzes typing patterns as a biometric identifier using:
1. Feature extraction from keystroke timings (hold time, flight time, digraph latency)
2. Autoencoder neural network for anomaly detection (learns normal typing patterns)
3. Falls back to statistical matching when insufficient training data
"""

import json
import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore', category=UserWarning)


class KeystrokeDynamics:
    """
    Analyzes keystroke timing patterns for user authentication using
    an autoencoder-based anomaly detection approach.

    The autoencoder learns a user's normal typing pattern. When a new
    keystroke sample has high reconstruction error, it indicates an anomaly
    (potentially a different person typing).
    """

    # Thresholds
    ANOMALY_MULTIPLIER = 3.0        # Flag if error > mean + multiplier * std of training errors
    SIMILARITY_THRESHOLD = 0.65     # Statistical fallback threshold
    MIN_SAMPLES_STATISTICAL = 3     # Min samples for statistical matching
    MIN_SAMPLES_AUTOENCODER = 5     # Min samples to train autoencoder
    MAX_STORED_SAMPLES = 30         # Max keystroke samples to store per user

    # Autoencoder architecture: 6 -> 4 -> 2 -> 4 -> 6 (bottleneck = 2)
    HIDDEN_LAYERS = (4, 2, 4)
    MAX_ITER = 500

    def __init__(self):
        pass

    def extract_features(self, keystroke_data: List[Dict]) -> Optional[Dict]:
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
            'hold_mean': float(np.mean(hold_times)),
            'hold_std': float(np.std(hold_times)) if len(hold_times) > 1 else 0.0,
            'flight_mean': float(np.mean(flight_times)),
            'flight_std': float(np.std(flight_times)) if len(flight_times) > 1 else 0.0,
            'digraph_mean': float(np.mean(digraph_times)) if digraph_times else 0.0,
            'digraph_std': float(np.std(digraph_times)) if len(digraph_times) > 1 else 0.0,
            'total_time': keystroke_data[-1].get('release', 0) - keystroke_data[0].get('press', 0),
            'num_keys': len(keystroke_data)
        }

    def _features_to_vector(self, features: Dict) -> np.ndarray:
        """Convert feature dict to numpy array for ML processing."""
        return np.array([
            features['hold_mean'],
            features['hold_std'],
            features['flight_mean'],
            features['flight_std'],
            features['digraph_mean'],
            features['digraph_std']
        ])

    def _train_autoencoder(self, samples: List[List[float]]) -> Tuple[MLPRegressor, StandardScaler, float]:
        """
        Train an autoencoder on the user's keystroke history.

        The autoencoder is an MLPRegressor trained to reconstruct its own input.
        Input = Output = keystroke feature vector.
        The bottleneck forces it to learn a compressed representation of
        the user's normal typing pattern.

        Returns:
            (autoencoder, scaler, adaptive_threshold)
        """
        X = np.array(samples)

        # Standardize features (zero mean, unit variance)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Train autoencoder (input = target = same data)
        autoencoder = MLPRegressor(
            hidden_layer_sizes=self.HIDDEN_LAYERS,
            activation='relu',
            solver='adam',
            max_iter=self.MAX_ITER,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.2 if len(samples) >= 10 else 0.0,
            n_iter_no_change=20,
            learning_rate='adaptive',
            learning_rate_init=0.001
        )

        # For small datasets, disable early stopping
        if len(samples) < 10:
            autoencoder.set_params(early_stopping=False)

        autoencoder.fit(X_scaled, X_scaled)

        # Compute adaptive threshold from training data reconstruction errors
        X_reconstructed = autoencoder.predict(X_scaled)
        training_errors = np.mean((X_scaled - X_reconstructed) ** 2, axis=1)
        max_training_error = np.max(training_errors)
        mean_error = np.mean(training_errors)
        std_error = np.std(training_errors)

        # Use the larger of two strategies:
        # 1. Mean + multiplier * std (statistical approach)
        # 2. Max training error * multiplier (accounts for generalization gap)
        stat_threshold = mean_error + self.ANOMALY_MULTIPLIER * max(std_error, mean_error)
        max_threshold = max_training_error * self.ANOMALY_MULTIPLIER

        adaptive_threshold = max(stat_threshold, max_threshold, 0.5)

        return autoencoder, scaler, adaptive_threshold

    def _compute_reconstruction_error(self, autoencoder: MLPRegressor,
                                       scaler: StandardScaler,
                                       features: np.ndarray) -> float:
        """
        Compute normalized reconstruction error for a single sample.
        Returns a value where lower = more similar to training data.
        """
        X = features.reshape(1, -1)
        X_scaled = scaler.transform(X)
        X_reconstructed = autoencoder.predict(X_scaled)
        # Mean squared error
        mse = np.mean((X_scaled - X_reconstructed) ** 2)
        return float(mse)

    def calculate_similarity(self, profile: Dict, current: Dict) -> float:
        """
        Statistical fallback: Calculate similarity between stored profile and current typing.
        Returns value 0-1 (1 = identical).
        """
        if not profile or not current:
            return 0.0

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
                diff = abs(profile_val - current_val) / max(profile_val, current_val)
                similarity = max(0, 1 - diff)

            total_similarity += similarity * weight
            total_weight += weight

        return total_similarity / total_weight if total_weight > 0 else 0.0

    def update_profile(self, existing_profile: Optional[Dict], new_features: Dict) -> Dict:
        """
        Update user's keystroke profile with new sample.
        Stores both the running average (for statistical fallback) and
        raw feature history (for autoencoder training).
        """
        feature_vector = [
            new_features['hold_mean'],
            new_features['hold_std'],
            new_features['flight_mean'],
            new_features['flight_std'],
            new_features['digraph_mean'],
            new_features['digraph_std']
        ]

        if not existing_profile:
            return {
                'samples': 1,
                'hold_mean': new_features['hold_mean'],
                'hold_std': new_features['hold_std'],
                'flight_mean': new_features['flight_mean'],
                'flight_std': new_features['flight_std'],
                'digraph_mean': new_features['digraph_mean'],
                'digraph_std': new_features['digraph_std'],
                'history': [feature_vector]
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
            'digraph_std': (1 - alpha) * existing_profile['digraph_std'] + alpha * new_features['digraph_std'],
        }

        # Maintain feature history for autoencoder training
        history = existing_profile.get('history', [])
        history.append(feature_vector)

        # Keep only the last MAX_STORED_SAMPLES
        if len(history) > self.MAX_STORED_SAMPLES:
            history = history[-self.MAX_STORED_SAMPLES:]

        updated['history'] = history
        return updated

    def verify(self, user_profile_json: Optional[str], keystroke_data: List[Dict]) -> Tuple[bool, float, str]:
        """
        Verify user based on keystroke dynamics.

        Uses autoencoder-based anomaly detection when enough samples exist,
        falls back to statistical comparison otherwise.

        Returns:
            (is_valid, similarity_score, message)
        """
        current_features = self.extract_features(keystroke_data)

        if not current_features:
            return True, 0.0, "Insufficient keystroke data"

        if not user_profile_json:
            return True, 1.0, "No profile yet - building"

        try:
            profile = json.loads(user_profile_json)
        except (json.JSONDecodeError, TypeError):
            return True, 1.0, "Invalid profile - rebuilding"

        samples = profile.get('samples', 0)
        history = profile.get('history', [])

        # Not enough samples yet - accept but flag
        if samples < self.MIN_SAMPLES_STATISTICAL:
            return True, 1.0, f"Building profile ({samples}/{self.MIN_SAMPLES_STATISTICAL})"

        current_vector = self._features_to_vector(current_features)

        # Try autoencoder-based detection if enough history
        if len(history) >= self.MIN_SAMPLES_AUTOENCODER:
            try:
                autoencoder, scaler, threshold = self._train_autoencoder(history)
                reconstruction_error = self._compute_reconstruction_error(
                    autoencoder, scaler, current_vector
                )

                # Convert reconstruction error to a similarity-like score (0-1)
                # Lower error = higher similarity
                anomaly_score = max(0.0, 1.0 - min(reconstruction_error / threshold, 1.0))

                if reconstruction_error <= threshold:
                    return True, anomaly_score, f"Autoencoder match (error: {reconstruction_error:.4f}, threshold: {threshold:.4f})"
                else:
                    return False, anomaly_score, f"Autoencoder anomaly detected (error: {reconstruction_error:.4f}, threshold: {threshold:.4f})"

            except Exception:
                # Autoencoder failed, fall back to statistical
                pass

        # Statistical fallback
        similarity = self.calculate_similarity(profile, current_features)

        if similarity >= self.SIMILARITY_THRESHOLD:
            return True, similarity, f"Statistical match ({similarity:.1%})"
        else:
            return False, similarity, f"Statistical mismatch ({similarity:.1%})"


# Global instance
keystroke_analyzer = KeystrokeDynamics()
