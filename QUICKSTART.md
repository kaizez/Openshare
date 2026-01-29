# Quick Start Guide

## Installation

```bash
pip install -r requirements.txt
```

## Run Application

```bash
python app.py
```

Access at: **http://localhost:5000**

## Default Login

- **Username:** `240612R`
- **Password:** `ispj2025`

## Test the System (Optional)

1. Start the application (`python app.py`)
2. In another terminal, run:
   ```bash
   pip install requests  # If not already installed
   python test_system.py
   ```

This will test all three detection rules and demonstrate the system capabilities.

## Key Files

- `app.py` - Main Flask application
- `siem_engine.py` - Detection logic
- `soar_engine.py` - Response/containment logic
- `templates/` - Web UI templates
- `db/idir.db` - SQLite database (created automatically)

For detailed documentation, see **README.md**

