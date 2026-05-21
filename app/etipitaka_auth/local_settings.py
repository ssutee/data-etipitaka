DEBUG = False

ACCOUNT_DEFAULT_HTTP_PROTOCOL = 'https'
HTTPS = True

CSRF_TRUSTED_ORIGINS = ['https://data.etipitaka.com']

EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = 'etipitaka@gmail.com'
EMAIL_HOST_PASSWORD = 'ph69*2pD'
EMAIL_PORT = 587

import os

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
