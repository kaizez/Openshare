"""
Flask application for SIEM/SOAR Backend API.
Provides API endpoints for log ingestion, playbook actions, and dashboard data.
"""

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import os
import secrets
import sys
import hashlib

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from src.database.connection import get_db_connection, init_database
from src.ingestion.siem_engine import get_siem_engine
from src.playbooks.playbook_engine import get_playbook_engine
import mysql.connector
import threading
import time

LOG_RETENTION_HOURS = 10
CLEANUP_INTERVAL_SECONDS = 1800  # 30 minutes
SESSION_IDLE_TIMEOUT_MINUTES = 10
SESSION_ABSOLUTE_TTL_HOURS = 8

ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


def _validate_log_payload(payload: dict):
    """
    Validate incoming ingestion payload. Returns None if valid,
    otherwise returns a string error message.
    """
    if not isinstance(payload, dict):
        return "Expected JSON object"

    required_fields = ["event_type", "log_source", "description"]
    for field in required_fields:
        val = payload.get(field)
        if not isinstance(val, str) or not val.strip():
            return f"Missing or invalid field: {field}"

    severity = payload.get("severity", "Info")
    if severity not in ALLOWED_SEVERITIES:
        return f"Invalid severity: {severity}"

    if len(payload.get("description", "")) > 5000:
        return "Description too long"

    return None


def _cleanup_old_logs():
    """Delete security_logs older than LOG_RETENTION_HOURS."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            'DELETE FROM security_logs WHERE timestamp < NOW() - INTERVAL %s HOUR',
            (LOG_RETENTION_HOURS,)
        )
        deleted = cursor.rowcount
        connection.commit()
        if deleted > 0:
            print(f"Log cleanup: deleted {deleted} old log(s)")
    except Exception as e:
        print(f"Log cleanup error: {e}")
        if connection:
            connection.rollback()
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


def _log_cleanup_loop():
    """Daemon loop: run cleanup, then sleep, repeat."""
    while True:
        _cleanup_old_logs()
        time.sleep(CLEANUP_INTERVAL_SECONDS)


def create_app():
    """Create and configure Flask application."""
    app = Flask(__name__)
    app.secret_key = os.getenv('SECRET_KEY')
    if not app.secret_key:
        raise EnvironmentError("SECRET_KEY environment variable is required")

    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",  # demo-friendly; for multi-instance use Redis
        default_limits=[],
    )

    # Initialize database on startup
    try:
        init_database()
    except Exception as e:
        print(f"Warning: Database initialization issue: {e}")

    # Start background log retention cleanup
    cleanup_thread = threading.Thread(target=_log_cleanup_loop, daemon=True)
    cleanup_thread.start()

    # ==================== AUTH HELPERS ====================

    def _verify_session_token(token: str) -> bool:
        """Verify session token with 10-minute idle timeout and absolute TTL."""
        if not token:
            return False

        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT token, username, created_at, last_seen, expires_at
                FROM session_tokens
                WHERE token = %s
                """,
                (token,),
            )
            row = cursor.fetchone()
            if not row:
                return False

            now = datetime.utcnow()

            created_at = row.get("created_at") or now
            last_seen = row.get("last_seen") or created_at
            expires_at = row.get("expires_at") or (created_at + timedelta(hours=SESSION_ABSOLUTE_TTL_HOURS))

            # If expires_at was missing (older schema), persist it once.
            if row.get("expires_at") is None:
                cursor.execute(
                    "UPDATE session_tokens SET expires_at = %s WHERE token = %s",
                    (expires_at, token),
                )

            # Idle timeout check
            if now - last_seen > timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES) or now >= expires_at:
                cursor.execute("DELETE FROM session_tokens WHERE token = %s", (token,))
                connection.commit()
                return False

            # Refresh last_seen on successful auth
            cursor.execute(
                "UPDATE session_tokens SET last_seen = %s WHERE token = %s",
                (now, token),
            )
            connection.commit()
            return True
        except mysql.connector.Error:
            return False
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def _get_username_for_token(token: str) -> str:
        """Get username associated with a session token."""
        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute('SELECT username FROM session_tokens WHERE token = %s', (token,))
            row = cursor.fetchone()
            return row['username'] if row else 'unknown'
        except mysql.connector.Error:
            return 'unknown'
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def _verify_api_key(api_key: str) -> bool:
        """Verify an API key against the database (SHA-256 hashed at rest)."""
        if not api_key:
            return False

        api_key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('''
                SELECT id FROM api_keys
                WHERE api_key = %s AND is_active = TRUE
            ''', (api_key_hash,))
            result = cursor.fetchone()
            if result:
                cursor.execute('''
                    UPDATE api_keys SET last_used = %s WHERE api_key = %s
                ''', (datetime.utcnow(), api_key_hash))
                connection.commit()
                return True
            return False
        except mysql.connector.Error:
            return False
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def require_auth(f):
        """Decorator: require session token or API key. Always returns JSON on failure."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('X-Session-Token')
            if token and _verify_session_token(token):
                return f(*args, **kwargs)

            api_key = request.headers.get('X-API-Key')
            if api_key:
                if _verify_api_key(api_key):
                    return f(*args, **kwargs)
                return jsonify({'error': 'Invalid API key'}), 401

            return jsonify({'error': 'Authentication required'}), 401
        return decorated_function

    def get_authenticated_username():
        """Resolve the username from the current request's auth context."""
        token = request.headers.get('X-Session-Token')
        if token:
            return _get_username_for_token(token)
        return 'api_key'

    # ==================== HEALTH CHECK ====================

    @app.route('/health')
    def health_check():
        """Health check endpoint for Docker/monitoring."""
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('SELECT 1')
            cursor.fetchone()
            cursor.close()
            connection.close()
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
        except Exception as e:
            print(f"Health check failed: {e}")
            return jsonify({
                'status': 'unhealthy',
                'database': 'disconnected',
                'timestamp': datetime.utcnow().isoformat()
            }), 503

    # ==================== LOG INGESTION ====================

    @app.route('/api/ingest_log', methods=['POST'])
    @limiter.limit("30 per minute")
    @require_auth
    def ingest_log():
        """
        API endpoint to ingest security logs.
        Accepts JSON data and processes through SIEM engine.
        """
        try:
            log_data = request.get_json()
            error = _validate_log_payload(log_data)
            if error:
                return jsonify({'error': error}), 400

            # Ensure timestamp is set
            if 'timestamp' not in log_data:
                log_data['timestamp'] = datetime.utcnow().isoformat()

            # Process through SIEM engine
            siem_engine = get_siem_engine()
            alert = siem_engine.process_log(log_data)

            response_data = {
                'status': 'success',
                'message': 'Log ingested successfully',
                'alert_triggered': alert is not None
            }

            if alert:
                response_data['alert'] = alert

            return jsonify(response_data), 200

        except Exception as e:
            print(f"Error ingesting log: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    # ==================== PLAYBOOK ACTIONS ====================

    @app.route('/api/playbook/block_ip', methods=['POST'])
    @require_auth
    def playbook_block_ip():
        """Manual playbook action: Block Attacker IP."""
        data = request.get_json()
        ip_address = data.get('ip_address', '').strip()
        reason = data.get('reason', 'Manual block by admin').strip()

        if not ip_address:
            return jsonify({'error': 'IP address is required'}), 400

        playbook_engine = get_playbook_engine()
        result = playbook_engine.block_attacker_ip(
            ip_address=ip_address,
            reason=reason,
            action_taken_by=get_authenticated_username()
        )

        return jsonify(result), 200 if result.get('status') == 'success' else 400

    @app.route('/api/playbook/terminate_session', methods=['POST'])
    @require_auth
    def playbook_terminate_session():
        """Manual playbook action: Terminate User Session."""
        data = request.get_json()
        user_id = data.get('user_id')
        session_id = data.get('session_id')
        reason = data.get('reason', 'Manual termination by admin').strip()

        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400

        playbook_engine = get_playbook_engine()
        result = playbook_engine.terminate_user_session(
            user_id=user_id,
            session_id=session_id,
            reason=reason,
            action_taken_by=get_authenticated_username()
        )

        return jsonify(result), 200 if result.get('status') == 'success' else 400

    @app.route('/api/playbook/quarantine_file', methods=['POST'])
    @require_auth
    def playbook_quarantine_file():
        """Manual playbook action: Quarantine File."""
        data = request.get_json()
        file_name = data.get('file_name', '').strip()
        file_path = data.get('file_path', '').strip()
        reason = data.get('reason', 'Manual quarantine by admin').strip()
        user_id = data.get('user_id')
        ip_address = data.get('ip_address')

        if not file_name:
            return jsonify({'error': 'File name is required'}), 400

        playbook_engine = get_playbook_engine()
        result = playbook_engine.quarantine_file(
            file_name=file_name,
            file_path=file_path if file_path else None,
            reason=reason,
            user_id=user_id,
            ip_address=ip_address,
            action_taken_by=get_authenticated_username()
        )

        return jsonify(result), 200 if result.get('status') == 'success' else 400

    @app.route('/api/playbook/release_ip', methods=['POST'])
    @require_auth
    def playbook_release_ip():
        """Manual playbook action: Release IP from quarantine."""
        data = request.get_json()
        ip_address = data.get('ip_address', '').strip()

        if not ip_address:
            return jsonify({'error': 'IP address is required'}), 400

        playbook_engine = get_playbook_engine()
        success = playbook_engine.release_ip(
            ip_address=ip_address,
            action_taken_by=get_authenticated_username()
        )

        if success:
            return jsonify({'status': 'success', 'message': f'IP {ip_address} released'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Failed to release IP'}), 400

    # ==================== API KEY MANAGEMENT ====================

    @app.route('/api/keys', methods=['GET'])
    @require_auth
    def list_api_keys():
        """List all API keys (without showing the actual keys)."""
        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute('''
                SELECT id, key_name, created_at, last_used, is_active, created_by
                FROM api_keys
                ORDER BY created_at DESC
            ''')
            keys = cursor.fetchall()
            for key in keys:
                if key.get('created_at'):
                    key['created_at'] = key['created_at'].isoformat()
                if key.get('last_used'):
                    key['last_used'] = key['last_used'].isoformat()
            return jsonify({'keys': keys}), 200
        except mysql.connector.Error as e:
            return jsonify({'error': str(e)}), 500
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    @app.route('/api/keys', methods=['POST'])
    @require_auth
    def create_api_key():
        """Create a new API key."""
        data = request.get_json() or {}
        key_name = data.get('key_name', '').strip()

        if not key_name:
            return jsonify({'error': 'Key name is required'}), 400

        # Generate a secure API key (store only SHA-256 hash)
        api_key = secrets.token_hex(32)
        api_key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('''
                INSERT INTO api_keys (key_name, api_key, created_at, created_by, is_active)
                VALUES (%s, %s, %s, %s, TRUE)
            ''', (key_name, api_key_hash, datetime.utcnow(), get_authenticated_username()))
            connection.commit()

            return jsonify({
                'status': 'success',
                'key_name': key_name,
                'api_key': api_key,
                'message': 'API key created. Save this key - it will not be shown again!'
            }), 201
        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            return jsonify({'error': str(e)}), 500
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    @app.route('/api/keys/<int:key_id>', methods=['DELETE'])
    @require_auth
    def revoke_api_key(key_id):
        """Revoke (deactivate) an API key."""
        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('''
                UPDATE api_keys SET is_active = FALSE WHERE id = %s
            ''', (key_id,))
            connection.commit()

            if cursor.rowcount > 0:
                return jsonify({'status': 'success', 'message': 'API key revoked'}), 200
            else:
                return jsonify({'error': 'API key not found'}), 404
        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            return jsonify({'error': str(e)}), 500
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    # ==================== HONEYTOKEN MANAGEMENT ====================

    @app.route('/api/honeytokens', methods=['GET'])
    @require_auth
    def list_honeytokens():
        """List all active honeytokens."""
        playbook_engine = get_playbook_engine()
        honeytokens = playbook_engine.get_honeytokens()
        return jsonify({'honeytokens': honeytokens}), 200

    @app.route('/api/honeytokens', methods=['POST'])
    @require_auth
    def create_honeytoken():
        """Create a new honeytoken."""
        data = request.get_json()
        file_name = data.get('file_name', '').strip()
        file_path = data.get('file_path', '').strip()
        description = data.get('description', '').strip()

        if not file_name:
            return jsonify({'error': 'File name is required'}), 400

        playbook_engine = get_playbook_engine()
        result = playbook_engine.create_honeytoken(
            file_name=file_name,
            file_path=file_path if file_path else None,
            description=description,
            created_by=get_authenticated_username()
        )

        return jsonify(result), 200 if result.get('status') == 'success' else 400

    # ==================== SESSION AUTH API ====================

    @app.route('/api/auth/login', methods=['POST'])
    def api_login():
        """Authenticate and return a session token for the remote dashboard."""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute(
                'SELECT id, username, password_hash FROM users WHERE username = %s',
                (username,)
            )
            user = cursor.fetchone()

            if user and check_password_hash(user['password_hash'], password):
                token = secrets.token_hex(32)

                # Store token in DB — survives Flask reloads
                cursor.execute(
                    'INSERT INTO session_tokens (token, username) VALUES (%s, %s)',
                    (token, user['username'])
                )

                cursor.execute(
                    'UPDATE users SET last_login = %s WHERE id = %s',
                    (datetime.utcnow(), user['id'])
                )
                connection.commit()
                return jsonify({'session_token': token, 'username': user['username']}), 200

            return jsonify({'error': 'Invalid credentials'}), 401
        except mysql.connector.Error as e:
            print(f"Database error during API login: {e}")
            return jsonify({'error': 'Internal error'}), 500
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    @app.route('/api/auth/logout', methods=['POST'])
    def api_logout():
        """Invalidate a remote session token."""
        token = request.headers.get('X-Session-Token')
        if token:
            connection = None
            cursor = None
            try:
                connection = get_db_connection()
                cursor = connection.cursor()
                cursor.execute('DELETE FROM session_tokens WHERE token = %s', (token,))
                connection.commit()
            except mysql.connector.Error:
                pass
            finally:
                if cursor:
                    cursor.close()
                if connection and connection.is_connected():
                    connection.close()
        return jsonify({'status': 'ok'}), 200

    # ==================== DASHBOARD DATA API ====================

    @app.route('/api/dashboard/data')
    @require_auth
    def dashboard_data():
        """Return all dashboard data as JSON for the remote frontend."""
        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            per_page = 20
            try:
                page = max(1, int(request.args.get('page', 1)))
            except (ValueError, TypeError):
                page = 1

            cursor.execute('SELECT COUNT(*) as count FROM security_logs')
            log_total = cursor.fetchone()['count']
            log_pages = max(1, (log_total + per_page - 1) // per_page)
            page = min(page, log_pages)
            offset = (page - 1) * per_page

            cursor.execute('''
                SELECT timestamp, log_source, event_type, description, severity, user_id, ip_address
                FROM security_logs
                ORDER BY timestamp DESC
                LIMIT %s OFFSET %s
            ''', (per_page, offset))
            logs = cursor.fetchall()
            for log in logs:
                if log.get('timestamp'):
                    log['timestamp'] = log['timestamp'].isoformat() if hasattr(log['timestamp'], 'isoformat') else str(log['timestamp'])

            cursor.execute('''
                SELECT alert_type, severity, description, user_id, ip_address, file_name, timestamp, status, mitre_technique, correlation_id
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 10
            ''')
            alerts = cursor.fetchall()
            for alert in alerts:
                if alert.get('timestamp'):
                    alert['timestamp'] = alert['timestamp'].isoformat() if hasattr(alert['timestamp'], 'isoformat') else str(alert['timestamp'])

            cursor.execute('SELECT COUNT(*) as count FROM security_logs WHERE severity = "Critical"')
            critical_count = cursor.fetchone()['count']

            cursor.execute('SELECT COUNT(*) as count FROM security_logs WHERE severity = "High"')
            high_count = cursor.fetchone()['count']

            cursor.execute('SELECT COUNT(*) as count FROM quarantined_ips WHERE status = "quarantined"')
            quarantined_ips_count = cursor.fetchone()['count']

            cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE status = "new"')
            new_alerts_count = cursor.fetchone()['count']

        except mysql.connector.Error as e:
            print(f"Error fetching dashboard data: {e}")
            logs = []
            alerts = []
            critical_count = high_count = quarantined_ips_count = new_alerts_count = 0
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

        playbook_engine = get_playbook_engine()
        quarantined_ips = playbook_engine.get_quarantined_ips()
        quarantined_files = playbook_engine.get_quarantined_files()

        return jsonify({
            'logs': logs,
            'log_page': page,
            'log_pages': log_pages,
            'log_total': log_total,
            'alerts': alerts,
            'stats': {
                'critical': critical_count,
                'high': high_count,
                'quarantined_ips': quarantined_ips_count,
                'new_alerts': new_alerts_count
            },
            'quarantined_ips': quarantined_ips,
            'quarantined_files': quarantined_files
        })

    # ==================== ADMIN API ====================

    @app.route('/api/admin/add', methods=['POST'])
    @require_auth
    def api_add_admin():
        """Create a new admin account via API."""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            password_hash = generate_password_hash(password)
            cursor.execute('''
                INSERT INTO users (username, password_hash, created_at)
                VALUES (%s, %s, %s)
            ''', (username, password_hash, datetime.utcnow()))
            connection.commit()

            return jsonify({'status': 'success', 'message': f'Admin {username} created'}), 201
        except mysql.connector.IntegrityError:
            if connection:
                connection.rollback()
            return jsonify({'error': 'Username already exists'}), 409
        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            print(f"Database error creating admin: {e}")
            return jsonify({'error': 'Internal error'}), 500
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    # ==================== BOOTSTRAP ====================

    # Initialize users from USERS env var (format: "user1:pass1,user2:pass2")
    users_env = os.getenv('USERS', '')
    if users_env:
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            for entry in users_env.split(','):
                entry = entry.strip()
                if ':' not in entry:
                    continue
                username, password = entry.split(':', 1)
                username, password = username.strip(), password.strip()
                if not username or not password:
                    continue
                cursor.execute('SELECT COUNT(*) FROM users WHERE username = %s', (username,))
                if cursor.fetchone()[0] == 0:
                    password_hash = generate_password_hash(password)
                    cursor.execute('''
                        INSERT INTO users (username, password_hash, created_at)
                        VALUES (%s, %s, %s)
                    ''', (username, password_hash, datetime.utcnow()))
                    print(f"User created: {username}")
            connection.commit()
            cursor.close()
            connection.close()
        except Exception as e:
            print(f"Warning: Could not create users: {e}")
    else:
        print("Warning: USERS not set. No users will be created.")

    return app
