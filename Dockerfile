# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install system dependencies (if any are needed, e.g., for Pillow or database connectors)
# RUN apt-get update && apt-get install -y --no-install-recommends some-package && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
# Copy only requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code FIRST
COPY . /app/

# Copy entrypoint script AFTER main code copy and make it executable
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create directories for logs and static files if they don't exist within the container context
# Note: Logs and db.sqlite3 are often better handled with volumes in production
RUN mkdir -p logs staticfiles media

# Collect static files
# Ensure DJANGO_SETTINGS_MODULE is set if needed, or manage via environment variables later
# Setting DEBUG=False for collectstatic is often a good practice
RUN DJANGO_SETTINGS_MODULE=arpf_ti.settings python manage.py collectstatic --noinput --clear

# Expose port 8000 for Gunicorn
EXPOSE 8000

# Run migrations (Optional: Often better done as a separate step or entrypoint script)
# RUN python manage.py migrate --noinput

# Set the entrypoint (optional if set in docker-compose.yml, but good for clarity)
# ENTRYPOINT ["/app/entrypoint.sh"]

# Command to run when container starts (now handled by entrypoint.sh)
# CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "arpf_ti.wsgi:application"]
