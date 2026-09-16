from django.contrib import admin
from django.urls import include, path, re_path
from django.views.generic import TemplateView
from django.views.i18n import set_language
from oauth2_provider import urls as oauth2_urls
from oauth2_provider.views import (
    AuthorizationView,
    IntrospectTokenView,
    OAuthServerMetadataView,
    RevokeTokenView,
    TokenView,
)

from user_data import views, auth_views
from user_data import content_views
from user_data import canon_views
from user_data import oauth_views
from user_data import passkey_views
from user_data import passkey_web_views
from user_data import recovery
from user_data import wellknown_views
from user_data.auth_urls import rest_auth_patterns

# Explicit allow-list, not oauth2_provider.urls.base_urlpatterns: that also
# wires up the device-code grant (device-authorization/, device/,
# device-confirm/<...>, device-grant-status/<...>), which this deployment
# does not intend to serve -- it is untested, unmetered, and renders
# django-oauth-toolkit's stock templates rather than this project's branded
# consent page. Only mount the grants this deployment actually supports.
oauth2_base_urlpatterns = [
    path('authorize/', AuthorizationView.as_view(), name='authorize'),
    path('token/', TokenView.as_view(), name='token'),
    path('revoke_token/', RevokeTokenView.as_view(), name='revoke-token'),
    path('introspect/', IntrospectTokenView.as_view(), name='introspect'),
]

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
    path('login/passkey/', passkey_web_views.login_passkey),
    path('signup/', TemplateView.as_view(template_name="signup.html")),
    path('signup/validate/', TemplateView.as_view(template_name="validate.html")),
    re_path(r'^account/confirm-email/(?P<key>[^/]+)/$',
            auth_views.account_confirm_email, name='account_confirm_email'),
    path('account/recover/passkey/begin/', recovery.recover_passkey_begin),
    path('account/recover/passkey/finish/', recovery.recover_passkey_finish),
    path('api/content/bookmarks/', content_views.bookmarks),
    path('api/content/highlights/', content_views.highlights),
    path('api/content/tags/', content_views.tags),
    path('api/content/history/', content_views.history),
    path('api/content/lexicon/', content_views.lexicon),
    path('api/content/summary/', content_views.summary),
    path('api/canon/editions/', canon_views.editions),
    path('api/canon/search/', canon_views.search),
    path('api/canon/passage/', canon_views.passage),
    path('api/canon/resolve/', canon_views.resolve),
    path('api/canon/dictionary/', canon_views.dictionary),
    path('api/passkeys/login/begin/', passkey_views.login_begin),
    path('api/passkeys/login/finish/', passkey_views.login_finish),
    path('api/passkeys/signup/begin/', passkey_views.signup_begin),
    path('api/passkeys/signup/finish/', passkey_views.signup_finish),
    path('api/passkeys/', passkey_views.passkey_list),
    path('api/passkeys/<int:passkey_id>/', passkey_views.passkey_detail),
    path('api/passkeys/register/begin/', passkey_views.register_begin),
    path('api/passkeys/register/finish/', passkey_views.register_finish),
    path('api/passkeys/password/remove/', passkey_views.password_remove),
    path('o/', include((oauth2_base_urlpatterns + oauth2_urls.dcr_urlpatterns,
                        'oauth2_provider'), namespace='oauth2_provider')),
    path('.well-known/oauth-authorization-server', OAuthServerMetadataView.as_view()),
    path('.well-known/apple-app-site-association', wellknown_views.apple_app_site_association),
    path('.well-known/assetlinks.json', wellknown_views.assetlinks),
    path('api/oauth/verify/', oauth_views.verify),
    path('rest-auth/', include((rest_auth_patterns, 'rest_auth'))),
    path('i18n/setlang/', set_language, name='set_language'),
    path('admin/', admin.site.urls),
    # Override Django's reset views (same names) with the recovery versions.
    # Dispatch (matching an incoming request path) tries urlpatterns in this
    # list's order and uses the first match, so these two views -- listed
    # ahead of the include below -- are what actually serve every request.
    # reverse(), however, is built by URLResolver._populate() walking
    # url_patterns in *reverse* order and appending to a per-name list it
    # then searches front-to-back -- so for a name repeated across two
    # patterns, reverse() resolves to whichever one is registered LAST in
    # this file, which here is django.contrib.auth.urls's own
    # 'password_reset'/'password_reset_confirm', included below, not the
    # lines right here. That is harmless only because both pairs of
    # patterns spell the identical path ('password_reset/' and
    # 'reset/<uidb64>/<token>/'); reverse('password_reset_confirm', ...)
    # therefore still produces the same URL either way. Do not let the two
    # spellings drift apart, or reverse() and dispatch will disagree.
    path('password_reset/', recovery.password_reset_view, name='password_reset'),
    path('reset/<uidb64>/<token>/', recovery.AccountRecoveryConfirmView.as_view(),
         name='password_reset_confirm'),
    path('', include('django.contrib.auth.urls')),
]
