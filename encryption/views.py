
from django.shortcuts import render, redirect
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from django.conf import settings
import random
import base64

from .models import OTPKeyMapping, EncryptionLog
from .utils.aes_utils import generate_key, encrypt_message, decrypt_message
from .utils.infobip_sms import send_sms, validate_phone_number

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

@csrf_protect
def index(request):
    """Main encryption page"""
    if request.method == 'POST':
        try:
            # Get form data
            message = request.POST.get('message', '').strip()
            phone = request.POST.get('phone', '').strip()
            
            # Validate inputs
            if not message:
                messages.error(request, 'Message cannot be empty')
                return render(request, 'encryption/index.html')
            
            if not phone:
                messages.error(request, 'Phone number cannot be empty')
                return render(request, 'encryption/index.html')
            
            if not validate_phone_number(phone):
                messages.error(request, 'Invalid phone number format. Use international format like +2547xxxxxxxx')
                return render(request, 'encryption/index.html')
            
            # Generate AES key and encrypt message
            aes_key = generate_key()
            encrypted_message = encrypt_message(message, aes_key)
            
            # Generate OTP
            otp = str(random.randint(100000, 999999))
            
            # Store OTP-key mapping in database
            OTPKeyMapping.objects.create(
                otp=otp,
                aes_key=base64.urlsafe_b64encode(aes_key).decode(),
                phone_number=phone
            )
            
            # Send SMS
            sms_message = f"Your OTP for message decryption is: {otp}. Valid for 10 minutes."
            status_code, response_text, success = send_sms(phone, sms_message)
            
            # Log the operation
            EncryptionLog.objects.create(
                operation='encrypt',
                phone_number=phone,
                success=success,
                ip_address=get_client_ip(request)
            )
            
            # Clean up expired OTPs
            OTPKeyMapping.cleanup_expired()
            
            context = {
                'encrypted_message': encrypted_message,
                'sms_status': response_text,
                'sms_success': success,
                'phone': phone
            }
            
            return render(request, 'encryption/result.html', context)
            
        except Exception as e:
            messages.error(request, f'Encryption failed: {str(e)}')
            return render(request, 'encryption/index.html')
    
    return render(request, 'encryption/index.html')

@csrf_protect
def decrypt(request):
    """Decryption page"""
    if request.method == 'POST':
        try:
            # Get form data
            encrypted_message = request.POST.get('encrypted', '').strip()
            otp = request.POST.get('otp', '').strip()
            
            # Validate inputs
            if not encrypted_message:
                messages.error(request, 'Encrypted message cannot be empty')
                return render(request, 'decryption/decrypt.html')
            
            if not otp or len(otp) != 6 or not otp.isdigit():
                messages.error(request, 'Invalid OTP format. Must be 6 digits')
                return render(request, 'decryption/decrypt.html')
            
            # Find OTP mapping
            try:
                otp_mapping = OTPKeyMapping.objects.get(otp=otp, used=False)
            except OTPKeyMapping.DoesNotExist:
                messages.error(request, 'Invalid or expired OTP')
                # Log failed attempt
                EncryptionLog.objects.create(
                    operation='decrypt',
                    success=False,
                    ip_address=get_client_ip(request)
                )
                return render(request, 'decryption/decrypt.html')
            
            # Check if OTP is expired
            if otp_mapping.is_expired():
                messages.error(request, 'OTP has expired')
                otp_mapping.delete()  # Clean up expired OTP
                # Log failed attempt
                EncryptionLog.objects.create(
                    operation='decrypt',
                    phone_number=otp_mapping.phone_number,
                    success=False,
                    ip_address=get_client_ip(request)
                )
                return render(request, 'decryption/decrypt.html')
            
            # Decode AES key
            aes_key = base64.urlsafe_b64decode(otp_mapping.aes_key.encode())
            
            # Decrypt message
            decrypted_message = decrypt_message(encrypted_message, aes_key)
            
            # Mark OTP as used
            otp_mapping.used = True
            otp_mapping.save()
            
            # Log successful decryption
            EncryptionLog.objects.create(
                operation='decrypt',
                phone_number=otp_mapping.phone_number,
                success=True,
                ip_address=get_client_ip(request)
            )
            
            # Clean up expired OTPs
            OTPKeyMapping.cleanup_expired()
            
            context = {
                'decrypted_message': decrypted_message,
                'phone': otp_mapping.phone_number
            }
            
            return render(request, 'decryption/decrypted.html', context)
            
        except Exception as e:
            messages.error(request, f'Decryption failed: {str(e)}')
            # Log failed attempt
            EncryptionLog.objects.create(
                operation='decrypt',
                success=False,
                ip_address=get_client_ip(request)
            )
            return render(request, 'decryption/decrypt.html')
    
    return render(request, 'decryption/decrypt.html')
