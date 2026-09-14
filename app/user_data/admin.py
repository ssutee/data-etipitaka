from django.contrib import admin
from oauth2_provider.admin import ApplicationAdmin
from oauth2_provider.models import Application
from .models import UserData, SyncData

class UserDataAdmin(admin.ModelAdmin):
    list_display = ('file', 'platform', 'created_at', 'deleted', 'user',)

class SyncDataAdmin(admin.ModelAdmin):
    list_display = ('file', 'platform', 'created_at', 'checksum', 'user',)


admin.site.register(UserData, UserDataAdmin)
admin.site.register(SyncData, SyncDataAdmin)

admin.site.unregister(Application)


@admin.register(Application)
class OAuthApplicationAdmin(ApplicationAdmin):
    # Only DOT's base + DCR routes are mounted; oauth2_provider:detail (which
    # Application.get_absolute_url reverses) does not exist here.
    view_on_site = False
