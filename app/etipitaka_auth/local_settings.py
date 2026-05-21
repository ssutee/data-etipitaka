import os

DEBUG = False

ACCOUNT_DEFAULT_HTTP_PROTOCOL = 'https'
HTTPS = True

CSRF_TRUSTED_ORIGINS = ['https://data.etipitaka.com']

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = 'etipitaka@gmail.com'
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
EMAIL_PORT = 587
DEFAULT_FROM_EMAIL = 'E-Tipitaka Administrator <etipitaka@gmail.com>'

DATABASES = {
    'default': {
        'ENGINE': os.environ.get('SQL_ENGINE', 'django.db.backends.postgresql'),
        'NAME': os.environ.get('SQL_DATABASE', 'etipitaka_data'),
        'USER': os.environ.get('SQL_USER', 'etipitaka'),
        'PASSWORD': os.environ.get('SQL_PASSWORD', 'u2-*^We#9aP'),
        'HOST': os.environ.get('SQL_HOST', 'db'),
        'PORT': os.environ.get('SQL_PORT', '5432'),
    }
}
