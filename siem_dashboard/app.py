"""
SIEM Dashboard — Lightweight frontend proxy.

This is the only piece that goes into the Integration branch.
It serves the dashboard UI and forwards all data/action requests
to Ayden's remote SIEM backend. No database, no engine, no heavy deps.

Set SIEM_URL in your environment to point at the SIEM host.
"""

import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = os.getenv('SIEM_DASHBOARD_SECRET', 'change-this-in-production')

SIEM_URL = os.getenv('SIEM_URL', 'http://localhost:5001').rstrip('/')


def _auth_headers():
    """Return headers carrying the current session token."""
    token = session.get('session_token')
    return {'X-Session-Token': token} if token else {}


# ==================== PAGES ====================

@app.route('/')
def index():
    if 'session_token' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        try:
            print(f"[SIEM Login] Attempting login for user: {username}", flush=True)
            print(f"[SIEM Login] Backend URL: {SIEM_URL}/api/auth/login", flush=True)

            resp = requests.post(
                f'{SIEM_URL}/api/auth/login',
                json={'username': username, 'password': password},
                timeout=10
            )

            print(f"[SIEM Login] Response status: {resp.status_code}", flush=True)
            print(f"[SIEM Login] Response body: {resp.text[:500]}", flush=True)

            if resp.status_code == 200:
                data = resp.json()
                if 'session_token' not in data:
                    print(f"[SIEM Login] ERROR: No session_token in response", flush=True)
                    return render_template('login.html', error='Backend returned invalid response (no session_token)')
                session['session_token'] = data['session_token']
                session['username'] = data.get('username', username)
                return redirect(url_for('dashboard'))
        except requests.RequestException as e:
            print(f"[SIEM Login] Connection error: {e}", flush=True)
            return render_template('login.html', error=f'Cannot connect to SIEM backend: {e}')

        return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')


@app.route('/logout')
def logout():
    token = session.get('session_token')
    if token:
        try:
            requests.post(f'{SIEM_URL}/api/auth/logout',
                          headers={'X-Session-Token': token}, timeout=5)
        except requests.RequestException:
            pass
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'session_token' not in session:
        return redirect(url_for('login'))

    try:
        resp = requests.get(f'{SIEM_URL}/api/dashboard/data',
                            headers=_auth_headers(), timeout=10)
        if resp.status_code == 401:
            session.clear()
            return redirect(url_for('login'))
        data = resp.json()
    except requests.RequestException:
        data = {
            'logs': [],
            'alerts': [],
            'stats': {'critical': 0, 'high': 0, 'quarantined_ips': 0, 'new_alerts': 0},
            'quarantined_ips': [],
            'quarantined_files': []
        }

    return render_template('dashboard.html',
                           logs=data['logs'],
                           alerts=data['alerts'],
                           stats=data['stats'],
                           quarantined_ips=data['quarantined_ips'],
                           quarantined_files=data['quarantined_files'],
                           username=session.get('username'))


@app.route('/add_admin', methods=['GET', 'POST'])
def add_admin():
    if 'session_token' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not password:
            return render_template('add_admin.html',
                                   error='Username and password are required',
                                   username=session.get('username'))

        if password != confirm_password:
            return render_template('add_admin.html',
                                   error='Passwords do not match',
                                   username=session.get('username'))

        try:
            resp = requests.post(
                f'{SIEM_URL}/api/admin/add',
                json={'username': username, 'password': password},
                headers=_auth_headers(),
                timeout=10
            )
            if resp.status_code == 201:
                return redirect(url_for('dashboard'))
            error = resp.json().get('error', 'Failed to create admin')
            return render_template('add_admin.html', error=error, username=session.get('username'))
        except requests.RequestException:
            return render_template('add_admin.html',
                                   error='Cannot connect to SIEM backend.',
                                   username=session.get('username'))

    return render_template('add_admin.html', username=session.get('username'))


# ==================== PROXY ====================

@app.route('/api/playbook/<action>', methods=['POST'])
def proxy_playbook(action):
    """Forward playbook actions to the remote SIEM. JS calls these unchanged."""
    if 'session_token' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

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


# ==================== ENTRY POINT ====================

if __name__ == '__main__':
    port = int(os.getenv('PORT', '5001'))

    # Generate self-signed certs if they don't exist
    cert_dir = '/app/certs'
    cert_file = f'{cert_dir}/cert.pem'
    key_file = f'{cert_dir}/key.pem'

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        os.makedirs(cert_dir, exist_ok=True)
        import subprocess
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-nodes',
            '-keyout', key_file, '-out', cert_file,
            '-days', '365', '-subj', '/C=SG/ST=Singapore/L=Singapore/O=OpenShare/CN=localhost'
        ], check=True)

    app.run(host='0.0.0.0', port=port, ssl_context=(cert_file, key_file))
