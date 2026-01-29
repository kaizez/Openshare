"""
GeoIP Lookup Module for Impossible Travel Detection.
Uses free ip-api.com service with caching to reduce API calls.
"""

import requests
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from math import radians, sin, cos, sqrt, atan2
import sys
import os

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from src.database.connection import get_db_connection
import mysql.connector


class GeoIPLookup:
    """GeoIP lookup with database caching."""

    # ip-api.com free tier: 45 requests per minute
    API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon"
    CACHE_DURATION_HOURS = 24  # Cache geo data for 24 hours

    def __init__(self):
        """Initialize GeoIP lookup."""
        self._request_count = 0
        self._last_reset = datetime.utcnow()

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits (45 req/min)."""
        now = datetime.utcnow()
        if (now - self._last_reset).total_seconds() >= 60:
            self._request_count = 0
            self._last_reset = now
        return self._request_count < 45

    def get_location(self, ip_address: str) -> Optional[Dict]:
        """
        Get geographic location for an IP address.

        Args:
            ip_address: IP address to lookup

        Returns:
            Dictionary with country, city, lat, lon or None if lookup fails
        """
        # Skip private/local IPs
        if self._is_private_ip(ip_address):
            return None

        # Check cache first
        cached = self._get_cached_location(ip_address)
        if cached:
            return cached

        # Check rate limit
        if not self._check_rate_limit():
            print(f"GeoIP rate limit reached, skipping lookup for {ip_address}")
            return None

        # Make API request
        try:
            response = requests.get(
                self.API_URL.format(ip=ip_address),
                timeout=5
            )
            self._request_count += 1

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    location = {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon')
                    }
                    # Cache the result
                    self._cache_location(ip_address, location)
                    return location
        except requests.RequestException as e:
            print(f"GeoIP lookup failed for {ip_address}: {e}")

        return None

    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP is private/local."""
        if not ip_address or ip_address == 'unknown':
            return True

        private_prefixes = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', '127.', '0.', 'localhost'
        ]
        return any(ip_address.startswith(prefix) for prefix in private_prefixes)

    def _get_cached_location(self, ip_address: str) -> Optional[Dict]:
        """Get cached location from database."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            # Check if cache is still valid (24 hours)
            cutoff = datetime.utcnow() - timedelta(hours=self.CACHE_DURATION_HOURS)

            cursor.execute('''
                SELECT country, country_code, city, latitude, longitude
                FROM geo_cache
                WHERE ip_address = %s AND cached_at > %s
            ''', (ip_address, cutoff))

            result = cursor.fetchone()
            if result:
                return {
                    'country': result['country'],
                    'country_code': result['country_code'],
                    'city': result['city'],
                    'latitude': float(result['latitude']) if result['latitude'] else None,
                    'longitude': float(result['longitude']) if result['longitude'] else None
                }
        except mysql.connector.Error as e:
            print(f"Error reading geo cache: {e}")
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

        return None

    def _cache_location(self, ip_address: str, location: Dict):
        """Cache location in database."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute('''
                INSERT INTO geo_cache (ip_address, country, country_code, city, latitude, longitude, cached_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    country = VALUES(country),
                    country_code = VALUES(country_code),
                    city = VALUES(city),
                    latitude = VALUES(latitude),
                    longitude = VALUES(longitude),
                    cached_at = VALUES(cached_at)
            ''', (
                ip_address,
                location.get('country'),
                location.get('country_code'),
                location.get('city'),
                location.get('latitude'),
                location.get('longitude'),
                datetime.utcnow()
            ))

            connection.commit()
        except mysql.connector.Error as e:
            print(f"Error caching geo location: {e}")
            if connection:
                connection.rollback()
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    @staticmethod
    def calculate_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate distance between two coordinates using Haversine formula.

        Args:
            lat1, lon1: First coordinate
            lat2, lon2: Second coordinate

        Returns:
            Distance in kilometers
        """
        R = 6371  # Earth's radius in kilometers

        lat1_rad = radians(lat1)
        lat2_rad = radians(lat2)
        delta_lat = radians(lat2 - lat1)
        delta_lon = radians(lon2 - lon1)

        a = sin(delta_lat/2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(delta_lon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))

        return R * c

    def check_impossible_travel(self, user_id: str, current_ip: str,
                                 current_time: datetime) -> Optional[Dict]:
        """
        Check if user's login represents impossible travel.

        Args:
            user_id: User identifier
            current_ip: Current login IP
            current_time: Current login timestamp

        Returns:
            Alert dictionary if impossible travel detected, None otherwise
        """
        # Get current location
        current_location = self.get_location(current_ip)
        if not current_location or not current_location.get('latitude'):
            return None

        # Get last login for this user
        last_login = self._get_last_login(user_id)
        if not last_login:
            # First login, record it
            self._record_login(user_id, current_ip, current_time, current_location)
            return None

        # Check if locations are different
        if not last_login.get('latitude') or not last_login.get('longitude'):
            self._record_login(user_id, current_ip, current_time, current_location)
            return None

        # Calculate distance
        distance_km = self.calculate_distance_km(
            last_login['latitude'], last_login['longitude'],
            current_location['latitude'], current_location['longitude']
        )

        # Calculate time difference in hours
        time_diff_hours = (current_time - last_login['login_time']).total_seconds() / 3600

        # Calculate required speed (km/h) - max realistic is ~900 km/h (airplane)
        if time_diff_hours > 0:
            required_speed = distance_km / time_diff_hours
        else:
            required_speed = float('inf')

        # Record current login
        self._record_login(user_id, current_ip, current_time, current_location)

        # If required speed > 900 km/h and distance > 500km, it's suspicious
        if required_speed > 900 and distance_km > 500:
            return {
                'alert_type': 'Impossible Travel',
                'severity': 'Critical',
                'description': (
                    f'User {user_id} logged in from {current_location["city"]}, '
                    f'{current_location["country"]} ({current_ip}) only '
                    f'{time_diff_hours:.1f} hours after logging in from '
                    f'{last_login["city"]}, {last_login["country"]}. '
                    f'Distance: {distance_km:.0f} km, Required speed: {required_speed:.0f} km/h'
                ),
                'user_id': user_id,
                'ip_address': current_ip,
                'timestamp': current_time.isoformat(),
                'rule': 'impossible_travel',
                'metadata': {
                    'distance_km': distance_km,
                    'time_diff_hours': time_diff_hours,
                    'required_speed_kmh': required_speed,
                    'from_location': f"{last_login['city']}, {last_login['country']}",
                    'to_location': f"{current_location['city']}, {current_location['country']}"
                }
            }

        return None

    def _get_last_login(self, user_id: str) -> Optional[Dict]:
        """Get user's last login record."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute('''
                SELECT ip_address, login_time, country, city, latitude, longitude
                FROM login_history
                WHERE user_id = %s
                ORDER BY login_time DESC
                LIMIT 1
            ''', (user_id,))

            result = cursor.fetchone()
            if result:
                return {
                    'ip_address': result['ip_address'],
                    'login_time': result['login_time'],
                    'country': result['country'],
                    'city': result['city'],
                    'latitude': float(result['latitude']) if result['latitude'] else None,
                    'longitude': float(result['longitude']) if result['longitude'] else None
                }
        except mysql.connector.Error as e:
            print(f"Error getting last login: {e}")
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

        return None

    def _record_login(self, user_id: str, ip_address: str,
                      login_time: datetime, location: Dict):
        """Record a login for impossible travel tracking."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute('''
                INSERT INTO login_history
                (user_id, ip_address, login_time, country, city, latitude, longitude)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                user_id,
                ip_address,
                login_time,
                location.get('country'),
                location.get('city'),
                location.get('latitude'),
                location.get('longitude')
            ))

            connection.commit()
        except mysql.connector.Error as e:
            print(f"Error recording login: {e}")
            if connection:
                connection.rollback()
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()


# Global instance
_geo_lookup = None

def get_geo_lookup() -> GeoIPLookup:
    """Get or create global GeoIP lookup instance."""
    global _geo_lookup
    if _geo_lookup is None:
        _geo_lookup = GeoIPLookup()
    return _geo_lookup
