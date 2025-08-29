import requests
import random
import string
from typing import Dict, Any, List
from datetime import datetime, timedelta
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class WhatsAppService:
    def __init__(self, access_token: str = None, phone_number_id: str = None):
        self.access_token = access_token or current_app.config.get('WHATSAPP_ACCESS_TOKEN')
        self.phone_number_id = phone_number_id or current_app.config.get('WHATSAPP_PHONE_NUMBER_ID')
        self.base_url = "https://graph.facebook.com/v18.0"
    
    def generate_otp(self, length: int = 6) -> str:
        """Generate OTP of specified length"""
        return ''.join(random.choices(string.digits, k=length))
    
    def send_otp(self, phone_number: str, otp: str, template_name: str = "otp_verification") -> Dict[str, Any]:
        """Send OTP via WhatsApp"""
        try:
            # Format phone number (add country code if not present)
            formatted_phone = self._format_phone_number(phone_number)
            
            url = f"{self.base_url}/{self.phone_number_id}/messages"
            
            payload = {
                "messaging_product": "whatsapp",
                "to": formatted_phone,
                "type": "template",
                "template": {
                    "name": template_name,
                    "language": {
                        "code": "en"
                    },
                    "components": [
                        {
                            "type": "body",
                            "parameters": [
                                {
                                    "type": "text",
                                    "text": otp
                                }
                            ]
                        }
                    ]
                }
            }
            
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"WhatsApp OTP sent successfully to {formatted_phone}")
            
            return {
                'success': True,
                'message_id': result.get('messages', [{}])[0].get('id'),
                'phone_number': formatted_phone,
                'otp': otp
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"WhatsApp API error: {e}")
            return {
                'success': False,
                'error': 'WhatsApp API request failed',
                'details': str(e)
            }
        except Exception as e:
            logger.error(f"WhatsApp OTP sending error: {e}")
            return {
                'success': False,
                'error': 'Failed to send OTP',
                'details': str(e)
            }
    
    def verify_otp(self, phone_number: str, submitted_otp: str, stored_otp: str) -> bool:
        """Verify submitted OTP"""
        return submitted_otp == stored_otp
    
    def send_message(self, phone_number: str, message: str) -> Dict[str, Any]:
        """Send simple text message via WhatsApp"""
        try:
            formatted_phone = self._format_phone_number(phone_number)
            
            url = f"{self.base_url}/{self.phone_number_id}/messages"
            
            payload = {
                "messaging_product": "whatsapp",
                "to": formatted_phone,
                "type": "text",
                "text": {
                    "body": message
                }
            }
            
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"WhatsApp message sent successfully to {formatted_phone}")
            
            return {
                'success': True,
                'message_id': result.get('messages', [{}])[0].get('id'),
                'phone_number': formatted_phone
            }
            
        except Exception as e:
            logger.error(f"WhatsApp message sending error: {e}")
            return {
                'success': False,
                'error': 'Failed to send message',
                'details': str(e)
            }
    
    def send_event_notification(self, phone_number: str, event_title: str, event_date: str, 
                               event_location: str) -> Dict[str, Any]:
        """Send event notification via WhatsApp"""
        try:
            formatted_phone = self._format_phone_number(phone_number)
            
            url = f"{self.base_url}/{self.phone_number_id}/messages"
            
            payload = {
                "messaging_product": "whatsapp",
                "to": formatted_phone,
                "type": "template",
                "template": {
                    "name": "event_notification",
                    "language": {
                        "code": "en"
                    },
                    "components": [
                        {
                            "type": "body",
                            "parameters": [
                                {
                                    "type": "text",
                                    "text": event_title
                                },
                                {
                                    "type": "text",
                                    "text": event_date
                                },
                                {
                                    "type": "text",
                                    "text": event_location
                                }
                            ]
                        }
                    ]
                }
            }
            
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Event notification sent successfully to {formatted_phone}")
            
            return {
                'success': True,
                'message_id': result.get('messages', [{}])[0].get('id'),
                'phone_number': formatted_phone
            }
            
        except Exception as e:
            logger.error(f"Event notification error: {e}")
            return {
                'success': False,
                'error': 'Failed to send event notification',
                'details': str(e)
            }
    
    def _format_phone_number(self, phone_number: str) -> str:
        """Format phone number for WhatsApp API"""
        # Remove any non-digit characters
        cleaned = ''.join(filter(str.isdigit, phone_number))
        
        # Add country code if not present (assuming India +91)
        if len(cleaned) == 10:
            return f"91{cleaned}"
        elif len(cleaned) == 12 and cleaned.startswith('91'):
            return cleaned
        else:
            return cleaned
    
    def get_webhook_verification(self, mode: str, token: str, challenge: str) -> str:
        """Handle WhatsApp webhook verification"""
        verify_token = current_app.config.get('WHATSAPP_VERIFY_TOKEN', 'your_verify_token')
        
        if mode == 'subscribe' and token == verify_token:
            logger.info("WhatsApp webhook verified successfully")
            return challenge
        else:
            logger.error("WhatsApp webhook verification failed")
            return "Verification failed"
    
    def process_webhook_message(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process incoming WhatsApp webhook messages"""
        try:
            entry = data.get('entry', [{}])[0]
            changes = entry.get('changes', [{}])[0]
            value = changes.get('value', {})
            messages = value.get('messages', [])
            
            if not messages:
                return {'success': True, 'message': 'No messages to process'}
            
            message = messages[0]
            phone_number = message.get('from')
            message_type = message.get('type')
            timestamp = message.get('timestamp')
            
            if message_type == 'text':
                text_data = message.get('text', {})
                text_content = text_data.get('body', '')
                
                return {
                    'success': True,
                    'phone_number': phone_number,
                    'message_type': message_type,
                    'content': text_content,
                    'timestamp': timestamp
                }
            else:
                return {
                    'success': True,
                    'phone_number': phone_number,
                    'message_type': message_type,
                    'timestamp': timestamp
                }
                
        except Exception as e:
            logger.error(f"Webhook message processing error: {e}")
            return {
                'success': False,
                'error': 'Failed to process webhook message',
                'details': str(e)
            }

class WhatsAppGroupService:
    def __init__(self, access_token: str = None, phone_number_id: str = None):
        self.access_token = access_token or current_app.config.get('WHATSAPP_ACCESS_TOKEN')
        self.phone_number_id = phone_number_id or current_app.config.get('WHATSAPP_PHONE_NUMBER_ID')
        self.base_url = "https://graph.facebook.com/v18.0"
    
    def create_group(self, name: str, description: str = "", phone_numbers: List[str] = None) -> Dict[str, Any]:
        """Create WhatsApp group"""
        try:
            url = f"{self.base_url}/{self.phone_number_id}/groups"
            
            payload = {
                "name": name,
                "description": description
            }
            
            if phone_numbers:
                formatted_numbers = [self._format_phone_number(phone) for phone in phone_numbers]
                payload["phone_numbers"] = formatted_numbers
            
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"WhatsApp group created successfully: {name}")
            
            return {
                'success': True,
                'group_id': result.get('id'),
                'group_name': name,
                'result': result
            }
            
        except Exception as e:
            logger.error(f"WhatsApp group creation error: {e}")
            return {
                'success': False,
                'error': 'Failed to create WhatsApp group',
                'details': str(e)
            }
    
    def add_member_to_group(self, group_id: str, phone_number: str) -> Dict[str, Any]:
        """Add member to WhatsApp group"""
        try:
            formatted_phone = self._format_phone_number(phone_number)
            
            url = f"{self.base_url}/{group_id}/members"
            
            payload = {
                "phone_numbers": [formatted_phone]
            }
            
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Member added to WhatsApp group: {phone_number}")
            
            return {
                'success': True,
                'phone_number': formatted_phone,
                'result': result
            }
            
        except Exception as e:
            logger.error(f"Add member to group error: {e}")
            return {
                'success': False,
                'error': 'Failed to add member to group',
                'details': str(e)
            }
    
    def send_group_message(self, group_id: str, message: str) -> Dict[str, Any]:
        """Send message to WhatsApp group"""
        try:
            url = f"{self.base_url}/{self.phone_number_id}/messages"
            
            payload = {
                "messaging_product": "whatsapp",
                "to": group_id,
                "type": "text",
                "text": {
                    "body": message
                }
            }
            
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Group message sent successfully to {group_id}")
            
            return {
                'success': True,
                'message_id': result.get('messages', [{}])[0].get('id'),
                'group_id': group_id
            }
            
        except Exception as e:
            logger.error(f"Group message sending error: {e}")
            return {
                'success': False,
                'error': 'Failed to send group message',
                'details': str(e)
            }
    
    def _format_phone_number(self, phone_number: str) -> str:
        """Format phone number for WhatsApp API"""
        cleaned = ''.join(filter(str.isdigit, phone_number))
        
        if len(cleaned) == 10:
            return f"91{cleaned}"
        elif len(cleaned) == 12 and cleaned.startswith('91'):
            return cleaned
        else:
            return cleaned
