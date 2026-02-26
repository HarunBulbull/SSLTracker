#!/bin/bash
# webTracker - Linux'ta çalıştırma scripti
set -e
cd "$(dirname "$0")"
if [ -d ".venv" ]; then
  source .venv/bin/activate
fi
export WEBTRACKER_DATA="${WEBTRACKER_DATA:-$(pwd)/data}"
mkdir -p "$WEBTRACKER_DATA"
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
