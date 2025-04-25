import os
from pathlib import Path
import ast # Add this import

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# Load SECRET_KEY from environment variable
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-fallback-key-change-me')

# SECURITY WARNING: don't run with debug turned on in production!
# Load DEBUG from environment variable, default to False
DEBUG = ast.literal_eval(os.environ.get('DJANGO_DEBUG', 'False'))

# Load ALLOWED_HOSTS from environment variable (comma-separated string)
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', '').split(',')

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # ARPF-TI apps
    'core',
    'dashboard',
    'alerts',
    'threat_intelligence',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Added WhiteNoise for static files
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Custom middleware for logging and monitoring
    'core.middleware.RequestLoggerMiddleware',
]

ROOT_URLCONF = 'arpf_ti.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'arpf_ti.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

# Restore logic to use DJANGO_DB_PATH from environment if set (for Docker volume), else default
DB_PATH = os.environ.get('DJANGO_DB_PATH', BASE_DIR / 'db.sqlite3')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': DB_PATH,
    }
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'staticfiles'),
]

# Enable WhiteNoise for static file serving
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Increase max upload size (e.g., to 100MB)
# Default is 2.5MB (2621440 bytes)
DATA_UPLOAD_MAX_MEMORY_SIZE = 104857600  # 100 * 1024 * 1024 bytes
FILE_UPLOAD_MAX_MEMORY_SIZE = 104857600 # Also set this for consistency

# Email configuration for alerts
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ.get('SMTP_SERVER') # Remove default
EMAIL_PORT = int(os.environ.get('SMTP_PORT', 587))
EMAIL_USE_TLS = ast.literal_eval(os.environ.get('SMTP_USE_TLS', 'True')) # Convert to bool
EMAIL_HOST_USER = os.environ.get('SMTP_USER') # Remove default
EMAIL_HOST_PASSWORD = os.environ.get('SMTP_PASSWORD') # Remove default
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', EMAIL_HOST_USER) # Use user if not set

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'arpf_ti.log'),
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'arpf_ti': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# ARPF-TI specific settings
# Threat intelligence update frequency in seconds
THREAT_INTEL_UPDATE_FREQUENCY = 3600  # Default: hourly

# Enable/disable features
ENABLE_ALERTS = True
ENABLE_AI_CLASSIFIER = True
ENABLE_DASHBOARD = True

# IP logging exclusion settings
EXCLUDE_HOST_IPS = True  # Auto-detect and exclude the host's own IP addresses
EXCLUDED_IPS = ['64.130.127.37', '3.88.244.164', '172.31.26.20']  # Manually excluded IPs

# Slack webhook for alerts (optional)
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL') # Remove default

# API keys for threat intelligence sources
API_KEY = os.environ.get('API_KEY') # Remove default

# Rules file path
RULES_FILE_PATH = os.path.join(BASE_DIR, 'config', 'rules.yaml')

# Create logs directory if it doesn't exist
os.makedirs(os.path.join(BASE_DIR, 'logs'), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'config'), exist_ok=True)
