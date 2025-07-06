from django.db import models
from django.utils import timezone
import datetime

# Create your models here.
class OTPKeyMapping(models.Model):
    """Model to store OTP to AES key mappings"""
    otp = models.CharField(max_length=6, unique=True)
    aes_key = models.TextField()  # Store base64 encoded key
    phone_number = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'otp_key_mappings'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"OTP: {self.otp} - Phone: {self.phone_number} - Used: {self.used}"
    
    def is_expired(self):
        """Check if OTP is expired (valid for 10 minutes)"""
        expiry_time = self.created_at + datetime.timedelta(minutes=10)
        return timezone.now() > expiry_time
    
    @classmethod
    def cleanup_expired(cls):
        """Remove expired OTP entries"""
        expiry_time = timezone.now() - datetime.timedelta(minutes=10)
        cls.objects.filter(created_at__lt=expiry_time).delete()

class EncryptionLog(models.Model):
    """Model to log encryption/decryption activities"""
    operation = models.CharField(max_length=20, choices=[
        ('encrypt', 'Encryption'),
        ('decrypt', 'Decryption'),
    ])
    phone_number = models.CharField(max_length=20, blank=True)
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    
    class Meta:
        db_table = 'encryption_logs'
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.operation} - {self.phone_number} - {self.success} - {self.timestamp}"
