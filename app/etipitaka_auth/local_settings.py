DEBUG = False

ACCOUNT_DEFAULT_HTTP_PROTOCOL = 'https'
HTTPS = True

EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = 'etipitaka@gmail.com'
EMAIL_HOST_PASSWORD = 'ph69*2pD'
EMAIL_PORT = 587

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'etipitaka_data',
        'USER': 'etipitaka',
        'PASSWORD': 'u2-*^We#9aP',
        'HOST': 'db',
        'PORT': '5432',        
    }
}
