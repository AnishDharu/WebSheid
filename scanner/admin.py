from django.contrib import admin
from .models import ScanJob, ScanFinding, ScanHistory, UserProfile, ScannerPlugin


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'target_url', 'status', 'security_score', 'risk_level', 'created_at']
    list_filter = ['status', 'risk_level']
    search_fields = ['target_url', 'user__username']
    readonly_fields = ['created_at', 'started_at', 'completed_at']


@admin.register(ScanFinding)
class ScanFindingAdmin(admin.ModelAdmin):
    list_display = ['id', 'scan', 'plugin', 'title', 'severity']
    list_filter = ['severity', 'plugin']
    search_fields = ['title', 'description']


@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ['id', 'scan', 'created_at']


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'organization', 'total_scans', 'created_at']


@admin.register(ScannerPlugin)
class ScannerPluginAdmin(admin.ModelAdmin):
    list_display = ['name', 'display_name', 'is_enabled', 'version']
    list_editable = ['is_enabled']
