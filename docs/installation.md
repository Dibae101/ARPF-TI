# Installation Guide

This guide provides detailed instructions for installing and configuring ARPF-TI on different environments.

## Prerequisites

- Python 3.10 or higher
- Git
- Pip package manager
- (Optional) Docker and Docker Compose for containerized deployment

## Standard Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ARPF-TI.git
cd ARPF-TI
```

### 2. Create and Activate Virtual Environment

```bash
# Create virtual environment
python -m venv env

# Activate on Linux/macOS
source env/bin/activate

# Activate on Windows
env\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the project root directory:

```bash
cp .env.example .env
```

Edit the `.env` file to configure:

- `DJANGO_SECRET_KEY`: Generate a secure random key
- `DJANGO_DEBUG`: Set to `False` for production
- `DJANGO_ALLOWED_HOSTS`: Comma-separated list of allowed hosts
- `SMTP_*`: Email settings for alert notifications
- `GEMINI_API_KEY`: Your Google Gemini API key (required for AI features)

### 5. Initialize Database

```bash
python manage.py migrate
```

### 6. Create Admin User

```bash
python manage.py createsuperuser
```

### 7. Start the Development Server

```bash
python manage.py runserver 0.0.0.0:8000
```

Access the platform at http://localhost:8000

## Docker Installation

For production or isolated testing environments, ARPF-TI can be deployed using Docker.

### 1. Clone and Configure

```bash
git clone https://github.com/yourusername/ARPF-TI.git
cd ARPF-TI
cp .env.example .env
```

Edit the `.env` file as described in the standard installation.

### 2. Build and Start Containers

```bash
docker-compose up -d
```

### 3. Create Admin User in Docker

```bash
docker-compose exec web python manage.py createsuperuser
```

Access the platform at http://localhost:8000

For more detailed Docker options, refer to the [docker-readme.md](../docker-readme.md) file.

## Production Deployment Recommendations

For production deployments, consider these additional steps:

1. **Use a Dedicated Database**: Configure a PostgreSQL or MySQL database instead of SQLite
2. **Set Up Nginx as Reverse Proxy**: For SSL termination and better performance
3. **Configure SSL Certificates**: Use Let's Encrypt for free SSL certificates
4. **Set Up Regular Backups**: Implement a backup strategy for the database and configuration
5. **Monitor System Resources**: Use tools like Prometheus and Grafana for monitoring

## Common Installation Issues

### Database Migration Errors

If you encounter database migration errors:

```bash
python manage.py migrate --run-syncdb
```

### Port Already in Use

If port 8000 is already in use:

```bash
# Find processes using port 8000
lsof -i:8000

# Use a different port
python manage.py runserver 0.0.0.0:8080
```

### Environment Activation Issues

If you have trouble activating the virtual environment, ensure you're in the project root and the environment exists:

```bash
# Check if virtual environment exists
ls env/

# Recreate if necessary 
python -m venv env --clear
```

## Next Steps

After installation:

1. [Configure rules](rule-configuration.md) to protect your application
2. Set up [threat intelligence sources](threat-intelligence.md)
3. Configure [AI integration](ai-integration.md) for enhanced protection

## System Requirements

- **Minimum**: 2 CPU cores, 4GB RAM, 20GB storage
- **Recommended**: 4 CPU cores, 8GB RAM, 40GB storage
- **Production**: 8 CPU cores, 16GB RAM, 100GB storage
