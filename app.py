from app import create_app

app = create_app()

if __name__ == '__main__':
    # Run with HTTPS using mkcert certificates
    app.run(
        debug=True,
        ssl_context=('certs/cert.pem', 'certs/key.pem'),
        host='127.0.0.1',
        port=5000
    )
