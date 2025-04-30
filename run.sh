#!/bin/bash

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if terminal supports colors
if [ -t 1 ]; then
    # Terminal supports colors
    USE_COLORS=true
else
    # Terminal doesn't support colors (e.g., when redirected to a file)
    USE_COLORS=false
fi

# Function to print colored text if supported
print_colored() {
    if [ "$USE_COLORS" = true ]; then
        echo -e "$1$2${NC}"
    else
        echo "$2"
    fi
}

# Find and activate the virtual environment
if [ -d "/home/ubuntu/ARPF-TI/env/bin" ]; then
    print_colored "${YELLOW}" "Activating virtual environment from /home/ubuntu/ARPF-TI/env/bin..."
    source /home/ubuntu/ARPF-TI/env/bin/activate
elif [ -d "/home/ubuntu/ARPF-TI/venv/bin" ]; then
    print_colored "${YELLOW}" "Activating virtual environment from /home/ubuntu/ARPF-TI/venv/bin..."
    source /home/ubuntu/ARPF-TI/venv/bin/activate
elif [ -d "env/bin" ]; then
    print_colored "${YELLOW}" "Activating virtual environment from env/bin..."
    source env/bin/activate
elif [ -d "venv/bin" ]; then
    print_colored "${YELLOW}" "Activating virtual environment from venv/bin..."
    source venv/bin/activate
else
    print_colored "${RED}" "Error: Can't find virtual environment. Please create one first."
    exit 1
fi

# Set the correct Python path to include your project
export PYTHONPATH=$PYTHONPATH:/home/ubuntu/ARPF-TI

# Check if Django is available
DJANGO_VERSION=$(python -c "import django; print(f'Django version: {django.__version__}')" 2>/dev/null)
if [ $? -eq 0 ]; then
    print_colored "${GREEN}" "Django is correctly installed and activated ✅ ${DJANGO_VERSION}"
else
    print_colored "${RED}" "Error: Django not found in the current environment ❌"
    exit 1
fi

# Look for manage.py in current directory or in the project path
MANAGE_PATH="manage.py"
if [ ! -f "$MANAGE_PATH" ]; then
    MANAGE_PATH="/home/ubuntu/ARPF-TI/manage.py"
    if [ ! -f "$MANAGE_PATH" ]; then
        print_colored "${RED}" "Error: Cannot find manage.py in the current directory or in /home/ubuntu/ARPF-TI/"
        exit 1
    fi
fi

# Run server or command if provided
if [ "$1" == "runserver" ]; then
    print_colored "${YELLOW}" "Starting development server..."
    python "$MANAGE_PATH" runserver 0.0.0.0:8000
elif [ "$1" == "makemigrations" ]; then
    print_colored "${YELLOW}" "Making migrations..."
    python "$MANAGE_PATH" makemigrations
elif [ "$1" == "migrate" ]; then
    print_colored "${YELLOW}" "Applying migrations..."
    python "$MANAGE_PATH" migrate
elif [ "$1" == "shell" ]; then
    print_colored "${YELLOW}" "Starting Django shell..."
    python "$MANAGE_PATH" shell
elif [ "$1" == "createsuperuser" ]; then
    print_colored "${YELLOW}" "Creating superuser..."
    python "$MANAGE_PATH" createsuperuser
elif [ "$1" == "collectstatic" ]; then
    print_colored "${YELLOW}" "Collecting static files..."
    python "$MANAGE_PATH" collectstatic --noinput
elif [ "$1" == "test" ]; then
    print_colored "${YELLOW}" "Running tests..."
    python "$MANAGE_PATH" test
elif [ "$1" == "check" ]; then
    print_colored "${YELLOW}" "Checking project..."
    python "$MANAGE_PATH" check
elif [ "$1" == "showmigrations" ]; then
    print_colored "${YELLOW}" "Showing migrations..."
    python "$MANAGE_PATH" showmigrations
elif [ -n "$1" ]; then
    # Run any other provided command
    print_colored "${YELLOW}" "Running command: $@"
    python "$MANAGE_PATH" "$@"
else
    print_colored "${YELLOW}" "No command specified. Available commands:"
    print_colored "${GREEN}" "  runserver       - Start the development server"
    print_colored "${GREEN}" "  makemigrations  - Create database migrations"
    print_colored "${GREEN}" "  migrate         - Apply database migrations"
    print_colored "${GREEN}" "  shell           - Start Django shell"
    print_colored "${GREEN}" "  createsuperuser - Create a superuser"
    print_colored "${GREEN}" "  collectstatic   - Collect static files"
    print_colored "${GREEN}" "  test            - Run tests"
    print_colored "${GREEN}" "  check           - Check for problems in project"
    print_colored "${GREEN}" "  showmigrations  - Show migration status"
fi