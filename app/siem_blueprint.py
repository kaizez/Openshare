"""
SIEM Dashboard Blueprint.

Integrates the standalone SIEM dashboard into the main OpenShare app.
- Auth is handled by the main app session (session['user_id'] + user.is_admin).
- SIEM engine token is stored as session['siem_token'] within the same session.
- All routes live under /siem.
"""

import os
import requests
from functools import wraps
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, session, jsonify
)

siem_bp = Blueprint('siem', __name__, url_prefix='/siem')

SIEM_URL = os.getenv('SIEM_URL', 'http://localhost:5001').rstrip('/')


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _get_user():
    """Return the User model for the current session, or None."""
    from app.models import User
    user_id = session.get('user_id')
    if not user_id:
        return None
    return User.query.get(user_id)


def require_admin(f):
    """Decorator: must be logged into main app as an admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = _get_user()
        if not user:
            return redirect(url_for('main.login'))
        if not user.is_admin:
            return redirect(url_for('main.admin_unauthorized'))
        return f(*args, **kwargs)
    return decorated


def require_siem_token(f):
    """Decorator: must also have an active SIEM engine session token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('siem_token'):
            return redirect(url_for('siem.connect'))
        return f(*args, **kwargs)
    return decorated


def _auth_headers():
    """Return X-Session-Token header for the SIEM engine."""
    token = session.get('siem_token')
    return {'X-Session-Token': token} if token else {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@siem_bp.route('/')
@require_admin
def index():
    if session.get('siem_token'):
        return redirect(url_for('siem.siem_dashboard'))
    return redirect(url_for('siem.connect'))


@siem_bp.route('/connect', methods=['GET', 'POST'])
@require_admin
def connect():
    """
    Authenticate with the SIEM engine.
    The main app session is already verified; this just gets a SIEM token.
    """
    if session.get('siem_token'):
        return redirect(url_for('siem.siem_dashboard'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        try:
            resp = requests.post(
                f'{SIEM_URL}/api/auth/login',
                json={'username': username, 'password': password},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                if 'session_token' in data:
                    session['siem_token'] = data['session_token']
                    session['siem_username'] = data.get('username', username)
                    return redirect(url_for('siem.siem_dashboard'))
                error = 'Backend returned an invalid response.'
            else:
                error = 'Invalid SIEM credentials.'
        except requests.RequestException as e:
            error = f'Cannot connect to SIEM backend: {e}'

    user = _get_user()
    return render_template('siem/connect.html', error=error,
                           username=user.username if user else '')


@siem_bp.route('/disconnect')
@require_admin
def disconnect():
    """Log out of the SIEM engine (does not log out of the main app)."""
    token = session.get('siem_token')
    if token:
        try:
            requests.post(f'{SIEM_URL}/api/auth/logout',
                          headers={'X-Session-Token': token}, timeout=5)
        except requests.RequestException:
            pass
    session.pop('siem_token', None)
    session.pop('siem_username', None)
    return redirect(url_for('siem.connect'))


@siem_bp.route('/dashboard')
@require_admin
@require_siem_token
def siem_dashboard():
    page = request.args.get('page', 1, type=int)
    try:
        resp = requests.get(f'{SIEM_URL}/api/dashboard/data',
                            headers=_auth_headers(),
                            params={'page': page},
                            timeout=10)
        if resp.status_code == 401:
            session.pop('siem_token', None)
            session.pop('siem_username', None)
            return redirect(url_for('siem.connect'))
        data = resp.json()
    except requests.RequestException:
        data = {
            'logs': [],
            'log_page': 1,
            'log_pages': 1,
            'log_total': 0,
            'alerts': [],
            'stats': {'critical': 0, 'high': 0, 'quarantined_ips': 0, 'new_alerts': 0},
            'quarantined_ips': [],
            'quarantined_files': [],
        }

    user = _get_user()
    return render_template('siem/dashboard.html',
                           logs=data['logs'],
                           log_page=data.get('log_page', 1),
                           log_pages=data.get('log_pages', 1),
                           log_total=data.get('log_total', 0),
                           alerts=data['alerts'],
                           stats=data['stats'],
                           quarantined_ips=data['quarantined_ips'],
                           quarantined_files=data['quarantined_files'],
                           siem_username=session.get('siem_username', ''),
                           username=user.username if user else '')


@siem_bp.route('/add_admin', methods=['GET', 'POST'])
@require_admin
@require_siem_token
def siem_add_admin():
    user = _get_user()
    error = None

    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not new_username or not password:
            error = 'Username and password are required.'
        elif password != confirm_password:
            error = 'Passwords do not match.'
        else:
            try:
                resp = requests.post(
                    f'{SIEM_URL}/api/admin/add',
                    json={'username': new_username, 'password': password},
                    headers=_auth_headers(),
                    timeout=10
                )
                if resp.status_code == 201:
                    return redirect(url_for('siem.siem_dashboard'))
                error = resp.json().get('error', 'Failed to create admin.')
            except requests.RequestException:
                error = 'Cannot connect to SIEM backend.'

    return render_template('siem/add_admin.html', error=error,
                           username=user.username if user else '',
                           siem_username=session.get('siem_username', ''))


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------

@siem_bp.route('/api/playbook/<action>', methods=['POST'])
@require_admin
@require_siem_token
def proxy_playbook(action):
    """Forward playbook actions to the SIEM engine."""
    try:
        resp = requests.post(
            f'{SIEM_URL}/api/playbook/{action}',
            json=request.get_json(),
            headers=_auth_headers(),
            timeout=10
        )
        return resp.text, resp.status_code, {'Content-Type': 'application/json'}
    except requests.RequestException as e:
        return jsonify({'error': f'Failed to reach SIEM backend: {e}'}), 503
