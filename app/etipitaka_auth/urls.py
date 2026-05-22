from django.contrib import admin
from django.urls import include, path, re_path
from django.views.generic import TemplateView
from django.views.i18n import set_language

from user_data import views, auth_views
from user_data.auth_urls import rest_auth_patterns

urlpatterns = [
    path('', views.index_view),
    path('sync_data_list/', views.sync_data_list),
    path('user_list/', views.user_list),
    path('sharing_list/', views.sharing_list),
    path('user/<int:pk>/', views.user),
    re_path(r'^user/(?P<pk>\d+)/(?P<name>.+)/$', views.download_user_data),
    path('sync_data/', views.upload_sync_data),
    re_path(r'^sync_data/(?P<name>.+)/$', views.download_sync_data),
    path('user_data/', views.user_data_view),
    path('user_data_list/', views.user_data_list),
    path('user_data/<int:pk>/', views.user_data_action),
    path('follower/<int:pk>/', views.follower),
    path('upload/', views.upload_view),
    path('login/', views.login_view),
    path('signup/', TemplateView.as_view(template_name="signup.html")),
    path('signup/validate/', TemplateView.as_view(template_name="validate.html")),
    re_path(r'^account/confirm-email/(?P<key>[^/]+)/$',
            auth_views.account_confirm_email, name='account_confirm_email'),
    path('rest-auth/', include((rest_auth_patterns, 'rest_auth'))),
    path('i18n/setlang/', set_language, name='set_language'),
    path('admin/', admin.site.urls),
    path('', include('django.contrib.auth.urls')),
]
