from django.urls import path

from . import auth_views

# Mounted under /rest-auth/
rest_auth_patterns = [
    path('login/', auth_views.rest_login, name='rest_login'),
    path('logout/', auth_views.rest_logout, name='rest_logout'),
    path('user/', auth_views.rest_user_details, name='rest_user_details'),
    path('registration/', auth_views.rest_register, name='rest_register'),
    path('registration/verify-email/', auth_views.rest_verify_email,
         name='rest_verify_email'),
]
