import requests
import json
from django.conf import settings

def send_sms(to, message):
    """
    Send SMS using Infobip API
    
    Args:
        to (str): Recipient phone number (e.g., "+2547xxxxxxxx")
        message (str): Message content
        
    Returns:
        tuple: (status_code, response_text, success)
    """
    url = f"{settings.INFOBIP_BASE_URL}/sms/2/text/advanced"
    
    headers = {
        "Authorization": f"App {settings.INFOBIP_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    payload = {
        "messages": [
            {
                "from": settings.INFOBIP_SENDER,
                "destinations": [{"to": to}],
                "text": message
            }
        ]
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        
        if response.status_code == 200:
            response_data = response.json()
            # Check if message was accepted
            if response_data.get("messages") and len(response_data["messages"]) > 0:
                message_status = response_data["messages"][0].get("status", {})
                if message_status.get("groupName") == "PENDING":
                    return response.status_code, "SMS sent successfully", True
                else:
                    return response.status_code, f"SMS failed: {message_status.get('description', 'Unknown error')}", False
            else:
                return response.status_code, "SMS failed: No message data in response", False
        else:
            return response.status_code, f"SMS failed: HTTP {response.status_code}", False
            
    except requests.exceptions.RequestException as e:
        return 0, f"SMS failed: Network error - {str(e)}", False
    except json.JSONDecodeError:
        return response.status_code, "SMS failed: Invalid response format", False
    except Exception as e:
        return 0, f"SMS failed: {str(e)}", False

def validate_phone_number(phone):
    """
    Basic phone number validation
    
    Args:
        phone (str): Phone number to validate
        
    Returns:
        bool: True if valid format, False otherwise
    """
    # Remove spaces and common separators
    phone = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    
    # Check if it starts with + and has 10-15 digits
    if phone.startswith("+") and len(phone) >= 11 and len(phone) <= 16:
        return phone[1:].isdigit()
    
    return False