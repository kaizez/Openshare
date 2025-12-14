"""
Custom IDIR (Intrusion Detection and Incident Response) Dashboard
A minimalistic, self-contained web application for security monitoring and response.
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import abort
from datetime import datetime
from functools import wraps
import sqlite3
import os
import json

from siem_engine import get_siem_engine
from soar_engine import get_soar_engine

app = Flask(__name__)
app.secret_key = os.urandom(24)  # In production, use a fixed secret key from environment variable

# Database configuration
DB_PATH = "db/idir.db"


def init_database():
    """Initialize database with required tables."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    
    # Create security_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            log_source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL
        )
    ''')
    
    # Create quarantined_ips table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quarantined_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            quarantined_at TEXT NOT NULL,
            released_at TEXT,
            status TEXT NOT NULL DEFAULT 'quarantined',
            reason TEXT,
            alerted_by TEXT
        )
    ''')
    
    # Check if initial admin user exists
    cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('240612R',))
    if cursor.fetchone()[0] == 0:
        # Create initial admin user
        password_hash = generate_password_hash('ispj2025')
        cursor.execute('''
            INSERT INTO users (username, password_hash, created_at)
            VALUES (?, ?, ?)
        ''', ('240612R', password_hash, datetime.utcnow().isoformat()))
    
    conn.commit()
    conn.close()
    
    # SOAR engine will initialize lazily when first used
    # The quarantined_ips table is already created above


def get_db_connection():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def require_login(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    """Redirect to login or dashboard."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT id, username, password_hash FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout and clear session."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@require_login
def dashboard():
    """Main security dashboard."""
    conn = get_db_connection()
    
    # Get top 10 most recent security logs
    logs = conn.execute('''
        SELECT timestamp, log_source, event_type, description, severity
        FROM security_logs
        ORDER BY timestamp DESC
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    # Get quarantined IPs
    soar_engine = get_soar_engine(DB_PATH)
    quarantined_ips = soar_engine.get_quarantined_ips()
    
    return render_template('dashboard.html', 
                         logs=logs, 
                         quarantined_ips=quarantined_ips,
                         username=session.get('username'))


@app.route('/api/ingest_log', methods=['POST'])
@require_login
def ingest_log():
    """
    API endpoint to ingest security logs.
    Accepts JSON data and processes through SIEM engine.
    """
    try:
        log_data = request.get_json()
        
        if not log_data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Ensure timestamp is set
        if 'timestamp' not in log_data:
            log_data['timestamp'] = datetime.utcnow().isoformat()
        
        # Process through SIEM engine
        siem_engine = get_siem_engine(DB_PATH)
        alert = siem_engine.process_log(log_data)
        
        response_data = {
            'status': 'success',
            'message': 'Log ingested successfully',
            'alert_triggered': alert is not None
        }
        
        # If alert triggered, process through SOAR engine
        if alert:
            soar_engine = get_soar_engine(DB_PATH)
            soar_response = soar_engine.initiate_response(alert)
            response_data['alert'] = alert
            response_data['soar_response'] = soar_response
        
        return jsonify(response_data), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/release_ip', methods=['POST'])
@require_login
def release_ip():
    """Release a quarantined IP address."""
    ip_address = request.form.get('ip_address', '').strip()
    
    if not ip_address:
        return redirect(url_for('dashboard'))
    
    soar_engine = get_soar_engine(DB_PATH)
    success = soar_engine.release_ip(ip_address)
    
    if success:
        return redirect(url_for('dashboard') + '?released=' + ip_address)
    else:
        return redirect(url_for('dashboard') + '?error=release_failed')


@app.route('/add_admin', methods=['GET', 'POST'])
@require_login
def add_admin():
    """Add a new admin account (web form)."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not password:
            return render_template('add_admin.html', error='Username and password are required')
        
        if password != confirm_password:
            return render_template('add_admin.html', error='Passwords do not match')
        
        conn = get_db_connection()
        try:
            password_hash = generate_password_hash(password)
            conn.execute('''
                INSERT INTO users (username, password_hash, created_at)
                VALUES (?, ?, ?)
            ''', (username, password_hash, datetime.utcnow().isoformat()))
            conn.commit()
            conn.close()
            return redirect(url_for('dashboard') + '?admin_added=' + username)
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('add_admin.html', error='Username already exists')
    
    return render_template('add_admin.html')


if __name__ == '__main__':
    # Initialize database on startup
    init_database()
    
    # Run Flask application
    app.run(debug=True, host='0.0.0.0', port=5000)

