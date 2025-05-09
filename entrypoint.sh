#!/bin/sh

# Exit immediately if a command exits with a non-zero status.
set -e

# Apply database migrations
echo "Applying database migrations..."
python manage.py migrate --noinput

# Collect static files (optional, but good practice if not done in Dockerfile)
# echo "Collecting static files..."
# python manage.py collectstatic --noinput

# Start Gunicorn server with fewer workers and increased timeout
echo "Starting Gunicorn..."
exec gunicorn --bind 0.0.0.0:8000 --workers 1 --timeout 300 arpf_ti.wsgi:application