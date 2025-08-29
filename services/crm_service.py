import requests
import base64
from typing import Dict, Any, List
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class FreshdeskCRM:
    def __init__(self, domain: str = None, api_key: str = None):
        self.domain = domain or current_app.config.get('FRESHDESK_DOMAIN')
        self.api_key = api_key or current_app.config.get('FRESHDESK_API_KEY')
        self.base_url = f"https://{self.domain}.freshdesk.com/api/v2"
    
    def _get_auth_header(self) -> str:
        """Get authorization header for Freshdesk API"""
        credentials = f"{self.api_key}:X"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded_credentials}"
    
    def create_ticket(self, subject: str, description: str, email: str, 
                     priority: int = 1, status: int = 2, category: str = "General",
                     tags: List[str] = None) -> Dict[str, Any]:
        """Create support ticket"""
        try:
            url = f"{self.base_url}/tickets"
            
            payload = {
                "subject": subject,
                "description": description,
                "email": email,
                "priority": priority,
                "status": status,
                "type": "Question",
                "category": category,
                "tags": tags or []
            }
            
            headers = {
                "Authorization": self._get_auth_header(),
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Freshdesk ticket created: {result['id']}")
            
            return {
                'success': True,
                'ticket_id': result['id'],
                'subject': result['subject'],
                'status': result['status'],
                'priority': result['priority'],
                'created_at': result['created_at'],
                'freshdesk_data': result
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Freshdesk API error: {e}")
            return {
                'success': False,
                'error': 'Freshdesk API request failed',
                'details': str(e)
            }
        except Exception as e:
            logger.error(f"Ticket creation error: {e}")
            return {
                'success': False,
                'error': 'Failed to create ticket',
                'details': str(e)
            }
    
    def update_ticket(self, ticket_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update support ticket"""
        try:
            url = f"{self.base_url}/tickets/{ticket_id}"
            
            headers = {
                "Authorization": self._get_auth_header(),
                "Content-Type": "application/json"
            }
            
            response = requests.put(url, json=data, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Freshdesk ticket updated: {ticket_id}")
            
            return {
                'success': True,
                'ticket_id': result['id'],
                'status': result['status'],
                'updated_at': result['updated_at'],
                'freshdesk_data': result
            }
            
        except Exception as e:
            logger.error(f"Ticket update error: {e}")
            return {
                'success': False,
                'error': 'Failed to update ticket',
                'details': str(e)
            }
    
    def get_ticket(self, ticket_id: int) -> Dict[str, Any]:
        """Get ticket details"""
        try:
            url = f"{self.base_url}/tickets/{ticket_id}"
            
            headers = {
                "Authorization": self._get_auth_header(),
                "Content-Type": "application/json"
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Freshdesk ticket retrieved: {ticket_id}")
            
            return {
                'success': True,
                'ticket_id': result['id'],
                'subject': result['subject'],
                'description': result['description'],
                'status': result['status'],
                'priority': result['priority'],
                'email': result['email'],
                'created_at': result['created_at'],
                'updated_at': result['updated_at'],
                'freshdesk_data': result
            }
            
        except Exception as e:
            logger.error(f"Get ticket error: {e}")
            return {
                'success': False,
                'error': 'Failed to get ticket',
                'details': str(e)
            }
    
    def get_tickets(self, email: str = None, status: int = None, 
                   page: int = 1, per_page: int = 30) -> Dict[str, Any]:
        """Get list of tickets"""
        try:
            url = f"{self.base_url}/tickets"
            
            params = {
                "page": page,
                "per_page": per_page
            }
            
            if email:
                params["email"] = email
            if status:
                params["status"] = status
            
            headers = {
                "Authorization": self._get_auth_header(),
                "Content-Type": "application/json"
            }
            
            response = requests.get(url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Freshdesk tickets retrieved: {len(result)} tickets")
            
            return {
                'success': True,
                'tickets': result,
                'count': len(result),
                'page': page,
                'per_page': per_page
            }
            
        except Exception as e:
            logger.error(f"Get tickets error: {e}")
            return {
                'success': False,
                'error': 'Failed to get tickets',
                'details': str(e)
            }
    
    def add_note_to_ticket(self, ticket_id: int, note: str, is_private: bool = False) -> Dict[str, Any]:
        """Add note to ticket"""
        try:
            url = f"{self.base_url}/tickets/{ticket_id}/notes"
            
            payload = {
                "body": note,
                "private": is_private
            }
            
            headers = {
                "Authorization": self._get_auth_header(),
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Note added to ticket: {ticket_id}")
            
            return {
                'success': True,
                'note_id': result['id'],
                'body': result['body'],
                'created_at': result['created_at'],
                'freshdesk_data': result
            }
            
        except Exception as e:
            logger.error(f"Add note error: {e}")
            return {
                'success': False,
                'error': 'Failed to add note',
                'details': str(e)
            }
    
    def close_ticket(self, ticket_id: int, resolution: str = None) -> Dict[str, Any]:
        """Close ticket"""
        try:
            data = {
                "status": 5  # Closed status
            }
            
            if resolution:
                data["resolution"] = resolution
            
            result = self.update_ticket(ticket_id, data)
            
            if result['success']:
                logger.info(f"Ticket closed: {ticket_id}")
            
            return result
            
        except Exception as e:
            logger.error(f"Close ticket error: {e}")
            return {
                'success': False,
                'error': 'Failed to close ticket',
                'details': str(e)
            }
    
    def get_ticket_conversations(self, ticket_id: int) -> Dict[str, Any]:
        """Get ticket conversations/notes"""
        try:
            url = f"{self.base_url}/tickets/{ticket_id}/conversations"
            
            headers = {
                "Authorization": self._get_auth_header(),
                "Content-Type": "application/json"
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Ticket conversations retrieved: {ticket_id}")
            
            return {
                'success': True,
                'conversations': result,
                'count': len(result)
            }
            
        except Exception as e:
            logger.error(f"Get conversations error: {e}")
            return {
                'success': False,
                'error': 'Failed to get conversations',
                'details': str(e)
            }
    
    def create_contact(self, name: str, email: str, phone: str = None, 
                      company: str = None) -> Dict[str, Any]:
        """Create contact in Freshdesk"""
        try:
            url = f"{self.base_url}/contacts"
            
            payload = {
                "name": name,
                "email": email
            }
            
            if phone:
                payload["phone"] = phone
            if company:
                payload["company_id"] = company
            
            headers = {
                "Authorization": self._get_auth_header(),
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Freshdesk contact created: {result['id']}")
            
            return {
                'success': True,
                'contact_id': result['id'],
                'name': result['name'],
                'email': result['email'],
                'freshdesk_data': result
            }
            
        except Exception as e:
            logger.error(f"Create contact error: {e}")
            return {
                'success': False,
                'error': 'Failed to create contact',
                'details': str(e)
            }
    
    def get_contact(self, contact_id: int) -> Dict[str, Any]:
        """Get contact details"""
        try:
            url = f"{self.base_url}/contacts/{contact_id}"
            
            headers = {
                "Authorization": self._get_auth_header(),
                "Content-Type": "application/json"
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Freshdesk contact retrieved: {contact_id}")
            
            return {
                'success': True,
                'contact_id': result['id'],
                'name': result['name'],
                'email': result['email'],
                'phone': result.get('phone'),
                'freshdesk_data': result
            }
            
        except Exception as e:
            logger.error(f"Get contact error: {e}")
            return {
                'success': False,
                'error': 'Failed to get contact',
                'details': str(e)
            }
