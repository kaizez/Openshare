#!/bin/bash

echo "======================================"
echo "   MoveIT - Secure File Sharing"
echo "======================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null
then
    echo "Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install requirements
echo "Installing dependencies..."
pip install -r requirements.txt

echo ""
echo "======================================"
echo "Starting MoveIT application..."
echo "Access the app at: http://localhost:5000"
echo "Press Ctrl+C to stop the server"
echo "======================================"
echo ""

# Run the application
python app.py
