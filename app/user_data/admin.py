from django.contrib import admin
from .models import UserData, SyncData

class UserDataAdmin(admin.ModelAdmin):
    list_display = ('file', 'platform', 'created_at', 'deleted', 'user',)

class SyncDataAdmin(admin.ModelAdmin):
    list_display = ('file', 'platform', 'created_at', 'checksum', 'user',)


admin.site.register(UserData, UserDataAdmin)
admin.site.register(SyncData, SyncDataAdmin)
