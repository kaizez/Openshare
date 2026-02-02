from app import create_app
import os

app = create_app()

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
