#!/bin/bash

# Activate the virtual environment
source /home/ubuntu/ARPF-TI/env/bin/activate

# Set the correct Python path to include your project
export PYTHONPATH=$PYTHONPATH:/home/ubuntu/ARPF-TI

# Check if Django is available
if python -c "import django; print(f'Django version: {django.__version__}')" > /dev/null; then
    echo "Django is correctly installed and activated ✅"
else
    echo "Error: Django not found in the current environment ❌"
    exit 1
fi

# Run server or command if provided
if [ "$1" == "runserver" ]; then
    echo "Starting development server..."
    python /home/ubuntu/ARPF-TI/manage.py runserver 0.0.0.0:8000
elif [ "$1" == "makemigrations" ]; then
    echo "Making migrations..."
    python /home/ubuntu/ARPF-TI/manage.py makemigrations
elif [ "$1" == "migrate" ]; then
    echo "Applying migrations..."
    python /home/ubuntu/ARPF-TI/manage.py migrate
elif [ "$1" == "shell" ]; then
    echo "Starting Django shell..."
    python /home/ubuntu/ARPF-TI/manage.py shell
elif [ "$1" == "createsuperuser" ]; then
    echo "Creating superuser..."
    python /home/ubuntu/ARPF-TI/manage.py createsuperuser
elif [ "$1" == "collectstatic" ]; then
    echo "Collecting static files..."
    python /home/ubuntu/ARPF-TI/manage.py collectstatic --noinput
elif [ "$1" == "test" ]; then
    echo "Running tests..."
    python /home/ubuntu/ARPF-TI/manage.py test
elif [ -n "$1" ]; then
    # Run any other provided command
    python /home/ubuntu/ARPF-TI/manage.py "$@"
else
    echo "No command specified. Available commands:"
    echo "  runserver       - Start the development server"
    echo "  makemigrations  - Create database migrations"
    echo "  migrate         - Apply database migrations"
    echo "  shell           - Start Django shell"
    echo "  createsuperuser - Create a superuser"
    echo "  collectstatic   - Collect static files"
    echo "  test            - Run tests"
fi