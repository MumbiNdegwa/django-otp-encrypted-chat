from django.contrib import admin
from .models import OTPKeyMapping, EncryptionLog

@admin.register(OTPKeyMapping)
class OTPKeyMappingAdmin(admin.ModelAdmin):
    list_display = ['otp', 'phone_number', 'created_at', 'used', 'is_expired']
    list_filter = ['used', 'created_at']
    search_fields = ['otp', 'phone_number']
    readonly_fields = ['created_at', 'aes_key']
    
    def is_expired(self, obj):
        return obj.is_expired()
    is_expired.boolean = True
    is_expired.short_description = 'Expired'

@admin.register(EncryptionLog)
class EncryptionLogAdmin(admin.ModelAdmin):
    list_display = ['operation', 'phone_number', 'success', 'timestamp', 'ip_address']
    list_filter = ['operation', 'success', 'timestamp']
    search_fields = ['phone_number', 'ip_address']
    readonly_fields = ['timestamp']
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False