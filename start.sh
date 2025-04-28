#!/bin/bash

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting ARPF-TI application...${NC}"

# Navigate to the project directory (if script is run from elsewhere)
cd "$(dirname "$0")"

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
if [ -d "env/bin" ]; then
    source env/bin/activate
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Virtual environment activated successfully.${NC}"
    else
        echo -e "${RED}Failed to activate virtual environment.${NC}"
        exit 1
    fi
else
    echo -e "${RED}Virtual environment not found at env/bin. Please check your setup.${NC}"
    exit 1
fi

# Check if Python is properly activated
if python -c "import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)"; then
    echo -e "${GREEN}Using Python from: $(which python)${NC}"
else
    echo -e "${RED}Virtual environment doesn't seem to be activated properly.${NC}"
    exit 1
fi

# Check if port 8000 is in use
echo -e "${YELLOW}Checking if port 8000 is in use...${NC}"
if lsof -i:8000 > /dev/null 2>&1; then
    echo -e "${YELLOW}Port 8000 is in use. Attempting to free it...${NC}"
    # Find the process using port 8000 and kill it
    pid=$(lsof -t -i:8000)
    if [ ! -z "$pid" ]; then
        echo -e "${YELLOW}Killing process $pid using port 8000...${NC}"
        kill -9 $pid
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Successfully killed process.${NC}"
        else
            echo -e "${RED}Failed to kill process. You may need to run this script with sudo.${NC}"
            exit 1
        fi
    fi
else
    echo -e "${GREEN}Port 8000 is available.${NC}"
fi

# Start the Django server
echo -e "${YELLOW}Starting Django server on 0.0.0.0:8000...${NC}"
echo -e "${GREEN}Application will be available at http://localhost:8000${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop the server.${NC}"
python manage.py runserver 0.0.0.0:8000