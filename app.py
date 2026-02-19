from app import create_app, csrf
import os
import sys
from flask import request

# Add FileTransfer to path for blueprint import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'FileTransfer'))

app = create_app()

# Register FileTransfer blueprint at root (main app)
from FileTransfer.app import bp as filetransfer_bp

# Exempt FileTransfer blueprint from CSRF BEFORE registering
csrf.exempt(filetransfer_bp)

app.register_blueprint(filetransfer_bp, url_prefix='')

# Register Retention Policy API blueprint (for future admin page)
from FileTransfer.retention_api import retention_bp
csrf.exempt(retention_bp)
app.register_blueprint(retention_bp)

# Register SIEM Dashboard blueprint
from app.siem_blueprint import siem_bp
csrf.exempt(siem_bp)
app.register_blueprint(siem_bp)

# Debug: Catch 400 errors to see what's causing them
@app.errorhandler(400)
def handle_400(e):
    print(f"[ERROR 400] Path: {request.path}", flush=True)
    print(f"[ERROR 400] Method: {request.method}", flush=True)
    print(f"[ERROR 400] Exception: {e}", flush=True)
    print(f"[ERROR 400] Description: {e.description if hasattr(e, 'description') else 'N/A'}", flush=True)
    return {'error': str(e.description) if hasattr(e, 'description') else str(e)}, 400

if __name__ == '__main__':
    is_docker = os.environ.get('DOCKER_ENV') == 'true'
    use_ssl = os.path.exists('certs/cert.pem') and os.path.exists('certs/key.pem')

    if use_ssl:
        # Run with HTTPS
        app.run(
            debug=True,
            ssl_context=('certs/cert.pem', 'certs/key.pem'),
            host='0.0.0.0' if is_docker else '127.0.0.1',
            port=5000
        )
    else:
        # Run without SSL
        app.run(
            debug=True,
            host='0.0.0.0',
            port=5000
        )
