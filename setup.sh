#!/usr/bin/env bash
set -e
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
mkdir -p instance
echo "Setup complete. Run: source venv/bin/activate && python app.py"
