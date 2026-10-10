# OpenShare

OpenShare is a Flask web application for sharing files with controlled access. It combines user authentication, encrypted file storage, classification-based download checks, owner approvals, and security monitoring in one interface.

## Features

- Account registration with email verification, password recovery, and Google sign-in integration.
- Authenticator-based multi-factor authentication (TOTP), recovery tools, and session controls.
- File uploads up to 500 MB, encrypted file contents and access codes, and file management.
- VirusTotal scanning when configured, forensic download watermarks, and file activity analysis.
- Background archival to an isolated storage database and configurable file retention.
- Administration tools for users, devices, file transfers, and security risk information.
- A SIEM dashboard at `/siem`, connected to a separately deployed SIEM engine.

### File classifications

| Classification | Download requirements |
| --- | --- |
| Public | File access code |
| Internal Use | File access code and TOTP |
| Classified | File access code, TOTP, and owner approval |

## Architecture

The application uses Python 3.11, Flask, MySQL 8, SQLAlchemy, and Docker Compose. The root `docker-compose.yml` starts these services:

| Service | Purpose |
| --- | --- |
| `app` | Authentication, file sharing, administration, and SIEM interface |
| `auth-db` | User and authentication data |
| `working-db` | Active file data and metadata |
| `storage-db` | Archived file data; no published host port |
| `sync-service` | Archives files and retrieves archived contents |
| `vt-worker` | Processes background VirusTotal scans |
| `retention-service` | Enforces file retention policies |
| `movelorh-db` | Additional database included in the Compose configuration |

The main app accesses the working database. Archival and retrieval go through the sync service, which can reach the isolated storage network.

## Installation

### 1. Prerequisites and clone

Install Git and Docker with the Docker Compose v2 plugin (`docker compose`). An SMTP account is required for user registration and email-based recovery.

```bash
git clone https://github.com/kaizez/Openshare.git
cd Openshare
```

Run the commands below from the repository root. Use the root Compose file for the full application; `FileTransfer/docker-compose.yaml` describes a separate standalone stack.

### 2. Configure environment variables

Create `.env` in the repository root using the following settings. Replace all `replace-with-...` values with your own values and use different database passwords.

```dotenv
SECRET_KEY=replace-with-a-long-random-secret

AUTH_DB_ROOT_PASSWORD=replace-with-auth-root-password
WORKING_DB_ROOT_PASSWORD=replace-with-working-root-password
WORKING_DB_USER=working_user
WORKING_DB_PASSWORD=replace-with-working-password
WORKING_DB_NAME=workingdb
STORAGE_DB_ROOT_PASSWORD=replace-with-storage-root-password
STORAGE_DB_USER=storage_user
STORAGE_DB_PASSWORD=replace-with-storage-password
STORAGE_DB_NAME=storagedb
MOVELORH_DB_ROOT_PASSWORD=replace-with-movelorh-root-password
MOVELORH_DB_USER=move_user
MOVELORH_DB_PASSWORD=replace-with-movelorh-password
MOVELORH_DB_NAME=movedb

MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=replace-with-smtp-username
MAIL_PASSWORD=replace-with-smtp-password
MAIL_DEFAULT_SENDER=replace-with-sender-email

VIRUSTOTAL_ENABLED=false
VIRUSTOTAL_API_KEY=
OLLAMA_HOST=
OLLAMA_API_KEY=
SIEM_URL=
SIEM_API_KEY=
```

Use an app password for SMTP providers that require one. Registration sends an email verification code and cannot complete without working SMTP settings. `.env` is ignored by Git; keep credentials out of commits.

### 3. Build and start

```bash
docker compose config --quiet
docker compose up -d --build
docker compose ps
docker compose logs -f app
```

The initial build downloads dependencies. Wait for the databases to become healthy and the application to start, then open **https://localhost:5005**. The image generates a self-signed certificate, so a local browser certificate warning is expected.

### 4. First sign-in

On a fresh database, startup creates a super administrator with username `admin` and password `admin`. Sign in at `/login`, complete any MFA setup prompted by the application, and change the password immediately.

Startup supports `DEFAULT_ADMIN_USERNAME`, `DEFAULT_ADMIN_PASSWORD`, and `DEFAULT_ADMIN_EMAIL`, but the root Compose file does not currently forward these variables. To customize the initial account, add them to `app.environment` before the first startup. Adding them only to `.env` will not pass them into the container, and they do not reset an existing administrator.

## How to use

### Register and sign in

1. Open `/register` and enter your account details.
2. Enter the verification code sent to your email. Registration codes expire after 10 minutes.
3. Sign in and configure MFA when prompted. Save any recovery information provided.

### Upload and share

1. Sign in and open `/upload`.
2. Choose a supported file and select Public, Internal Use, or Classified.
3. Submit the upload and share the resulting file details and access code with the intended recipient.
4. Review the scan status and manage the upload through the file list.

### Download and approve access

1. Open `/download` and enter the shared access code.
2. Complete the TOTP check for Internal Use or Classified files.
3. For Classified files, request access and wait for owner approval.
4. Download after all required checks succeed. Archived contents are retrieved through the sync service.

Owners review requests at `/pending-approvals-page`. Administrators access management tools at `/admin/dashboard` and file-transfer controls at `/admin/filetransfer`.

## Optional integrations

| Integration | Configuration |
| --- | --- |
| VirusTotal | Set `VIRUSTOTAL_ENABLED=true` and provide `VIRUSTOTAL_API_KEY`; recreate `app` and `vt-worker`. |
| Google sign-in | Set `GOOGLE_CLIENT_SECRET` and configure the OAuth application and callback. The client ID is currently defined in `app/__init__.py`; update it for your own OAuth application. |
| reCAPTCHA | Set `RECAPTCHA_SITE_KEY` and `RECAPTCHA_SECRET_KEY` for your domain. |
| AI chatbot | AI routes are in `app/routes.py`. Review their endpoint and model configuration before use; the current routes include a hardcoded external endpoint. Compose exposes `OLLAMA_HOST` and `OLLAMA_API_KEY`, but these do not override every route. |
| SIEM | Deploy the separate OpenShare-SIEM engine, set `SIEM_URL` to an address reachable from the app container, and provide `SIEM_API_KEY` as required. Open `/siem` to connect. |

The root stack does not start the SIEM engine. Inside a container, `localhost` refers to that container; use an appropriate network hostname or reachable host address for external services.

After changing `.env`, run `docker compose up -d` to recreate affected containers.

## Maintenance

```bash
# Check service status
docker compose ps

# Follow application and background service logs
docker compose logs -f app sync-service vt-worker retention-service

# Rebuild after code or dependency changes
docker compose up -d --build

# Stop services and retain database volumes
docker compose down
```

Database data, encryption keys, and retention settings use Docker volumes; uploads are also mounted from `./uploads`. Back up databases, uploads, and encryption keys together. Losing keys can make encrypted files unreadable. `docker compose down -v` deletes named volumes; use it only for an intentional reset.

The supplied entry point runs Flask with debugging enabled and uses a self-signed certificate. This is a development/demo setup; a public deployment needs a production server configuration, trusted TLS, and configured credentials and integrations.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| App unavailable | Run `docker compose ps` and `docker compose logs --tail=100 app`; use HTTPS on port 5005. |
| Database startup fails | Check database logs and `.env` passwords. Changing environment passwords does not update users in an existing MySQL volume. |
| Registration email fails | Check SMTP host, port, TLS, sender, and provider authentication settings. |
| Download blocked | Check the access code, classification requirements, scan status, and owner approval. |
| Archived download fails | Check `sync-service` and `storage-db` status and logs. |
| SIEM connection fails | Confirm the separate engine is running and reachable from the app container. |
| Host port in use | Change the host side of the relevant `ports` mapping in the root Compose file. |

## Repository guide

```text
app.py                  Combined Flask entry point
app/                    Authentication, admin routes, security logic, and templates
FileTransfer/           File sharing, encryption, scanning, archival, and retention
siem_dashboard/         Standalone dashboard (not started by root Compose)
docker-compose.yml      Full application stack
Dockerfile              Main application image
requirements.txt        Main Python dependencies
```

See [FILETRANSFER_OVERVIEW.md](FILETRANSFER_OVERVIEW.md) for file-transfer implementation details. [SIEM_DASHBOARD.md](SIEM_DASHBOARD.md) explains the SIEM engine relationship but includes older standalone dashboard instructions; the root stack now integrates the interface at `/siem`.
