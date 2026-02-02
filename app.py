from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    # Check if running in Docker (no SSL certs available)
    use_ssl = os.path.exists('certs/cert.pem') and os.path.exists('certs/key.pem')

    if use_ssl:
        # Run with HTTPS using mkcert certificates (local development)
        app.run(
            debug=True,
            ssl_context=('certs/cert.pem', 'certs/key.pem'),
            host='127.0.0.1',
            port=5000
        )
    else:
        # Run without SSL (Docker environment)
        app.run(
            debug=True,
            host='0.0.0.0',
            port=5000
        )
