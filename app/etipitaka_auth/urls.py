"""etipitaka_auth URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Import the include() function: from django.conf.urls import url, include
    3. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf.urls import url, include
from django.contrib import admin
from django.views.generic import TemplateView
from django.contrib.auth import views as auth_views

urlpatterns = [
    url(r'^$', 'user_data.views.index_view'),
    url(r'^sync_data_list/$', 'user_data.views.sync_data_list'),
    url(r'^user_list/$', 'user_data.views.user_list'),
    url(r'^sharing_list/$', 'user_data.views.sharing_list'),
    url(r'^user/(?P<pk>\d+)/$', 'user_data.views.user'),
    url(r'^user/(?P<pk>\d+)/(?P<name>.+)/$', 'user_data.views.download_user_data'),
    url(r'^sync_data/$', 'user_data.views.upload_sync_data'),
    url(r'^sync_data/(?P<name>.+)/$', 'user_data.views.download_sync_data'),
    url(r'^user_data/$', 'user_data.views.user_data_view'),
    url(r'^user_data_list/$', 'user_data.views.user_data_list'),
    url(r'^user_data/(?P<pk>\d+)/$', 'user_data.views.user_data_action'),
    url(r'^follower/(?P<pk>\d+)/$', 'user_data.views.follower'),
    url(r'^upload/$', 'user_data.views.upload_view'),    
    url(r'^login/$', 'user_data.views.login_view'),    
    url(r'^signup/$', TemplateView.as_view(template_name="signup.html")),
    url(r'^signup/validate/$', TemplateView.as_view(template_name="validate.html")),
    url(r'^admin/', admin.site.urls),
    url(r'^rest-auth/', include('rest_auth.urls')),
    url(r'^rest-auth/registration/', include('rest_auth.registration.urls')),
    url(r'^account/', include('allauth.urls')),
    url('^', include('django.contrib.auth.urls')),
]
