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

print_colored "${YELLOW}" "Starting ARPF-TI application..."

# Navigate to the project directory (if script is run from elsewhere)
cd "$(dirname "$0")"

# Activate virtual environment
print_colored "${YELLOW}" "Activating virtual environment..."
if [ -d "env/bin" ]; then
    source env/bin/activate
    if [ $? -eq 0 ]; then
        print_colored "${GREEN}" "Virtual environment activated successfully."
    else
        print_colored "${RED}" "Failed to activate virtual environment."
        exit 1
    fi
elif [ -d "venv/bin" ]; then
    source venv/bin/activate
    if [ $? -eq 0 ]; then
        print_colored "${GREEN}" "Virtual environment activated successfully."
    else
        print_colored "${RED}" "Failed to activate virtual environment."
        exit 1
    fi
else
    print_colored "${RED}" "Virtual environment not found at env/bin or venv/bin. Please check your setup."
    exit 1
fi

# Check if Python is properly activated
if python -c "import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)"; then
    print_colored "${GREEN}" "Using Python from: $(which python)"
    
    # Check Django version
    DJANGO_VERSION=$(python -c "import django; print(django.__version__)" 2>/dev/null)
    if [ $? -eq 0 ]; then
        print_colored "${GREEN}" "Django version: ${DJANGO_VERSION}"
    else
        print_colored "${RED}" "Django not found in the current environment."
        exit 1
    fi
else
    print_colored "${RED}" "Virtual environment doesn't seem to be activated properly."
    exit 1
fi

# Check if port 8000 is in use
print_colored "${YELLOW}" "Checking if port 8000 is in use..."
if command -v lsof >/dev/null 2>&1; then
    if lsof -i:8000 > /dev/null 2>&1; then
        print_colored "${YELLOW}" "Port 8000 is in use."
        
        # Show what process is using the port
        if command -v lsof >/dev/null 2>&1; then
            print_colored "${YELLOW}" "Current process using port 8000:"
            lsof -i:8000
        fi
        
        read -p "Do you want to kill the process using port 8000? (y/n): " kill_process
        if [[ "$kill_process" == "y" || "$kill_process" == "Y" ]]; then
            pid=$(lsof -t -i:8000)
            if [ ! -z "$pid" ]; then
                print_colored "${YELLOW}" "Killing process $pid using port 8000..."
                kill -9 $pid
                if [ $? -eq 0 ]; then
                    print_colored "${GREEN}" "Successfully killed process."
                else
                    print_colored "${RED}" "Failed to kill process. You may need to run this script with sudo."
                    exit 1
                fi
            fi
        else
            print_colored "${YELLOW}" "Please free up port 8000 and try again."
            exit 1
        fi
    else
        print_colored "${GREEN}" "Port 8000 is available."
    fi
else
    print_colored "${YELLOW}" "Command 'lsof' not found. Unable to check if port is in use."
    print_colored "${YELLOW}" "If the server fails to start, it might be because port 8000 is in use."
fi

# Apply any pending migrations automatically
print_colored "${YELLOW}" "Checking for pending migrations..."
python manage.py showmigrations --list | grep "\[ \]" > /dev/null
if [ $? -eq 0 ]; then
    print_colored "${YELLOW}" "Found pending migrations. Applying them now..."
    python manage.py migrate
    if [ $? -eq 0 ]; then
        print_colored "${GREEN}" "Migrations applied successfully."
    else
        print_colored "${RED}" "Failed to apply migrations."
        read -p "Do you want to continue anyway? (y/n): " continue_anyway
        if [[ ! "$continue_anyway" == "y" && ! "$continue_anyway" == "Y" ]]; then
            exit 1
        fi
    fi
else
    print_colored "${GREEN}" "Database is up to date, no migrations needed."
fi

# Start the Django server
print_colored "${YELLOW}" "Starting Django server on 0.0.0.0:8000..."
print_colored "${GREEN}" "Application will be available at http://localhost:8000"
print_colored "${YELLOW}" "Press Ctrl+C to stop the server."
python manage.py runserver 0.0.0.0:8000