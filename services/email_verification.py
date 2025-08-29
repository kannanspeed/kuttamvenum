import re
from typing import List, Dict, Any
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class PoliticalPartyVerification:
    def __init__(self):
        self.party_domains = current_app.config.get('POLITICAL_PARTY_DOMAINS', [
            'dmk.in', 'aiadmk.in', 'bjp.org', 'inc.in', 'cpi.org',
            'cpim.org', 'ncp.org', 'sp.org', 'bsp.org', 'aap.org',
            'tdp.org', 'ysrcp.org', 'jdu.org', 'rjd.org', 'lsp.org'
        ])
        
        # Extended party mapping
        self.party_map = {
            'dmk.in': {
                'name': 'Dravida Munnetra Kazhagam',
                'short_name': 'DMK',
                'state': 'Tamil Nadu',
                'verification_level': 'verified'
            },
            'aiadmk.in': {
                'name': 'All India Anna Dravida Munnetra Kazhagam',
                'short_name': 'AIADMK',
                'state': 'Tamil Nadu',
                'verification_level': 'verified'
            },
            'bjp.org': {
                'name': 'Bharatiya Janata Party',
                'short_name': 'BJP',
                'state': 'National',
                'verification_level': 'verified'
            },
            'inc.in': {
                'name': 'Indian National Congress',
                'short_name': 'INC',
                'state': 'National',
                'verification_level': 'verified'
            },
            'cpi.org': {
                'name': 'Communist Party of India',
                'short_name': 'CPI',
                'state': 'National',
                'verification_level': 'verified'
            },
            'cpim.org': {
                'name': 'Communist Party of India (Marxist)',
                'short_name': 'CPI(M)',
                'state': 'National',
                'verification_level': 'verified'
            },
            'ncp.org': {
                'name': 'Nationalist Congress Party',
                'short_name': 'NCP',
                'state': 'Maharashtra',
                'verification_level': 'verified'
            },
            'sp.org': {
                'name': 'Samajwadi Party',
                'short_name': 'SP',
                'state': 'Uttar Pradesh',
                'verification_level': 'verified'
            },
            'bsp.org': {
                'name': 'Bahujan Samaj Party',
                'short_name': 'BSP',
                'state': 'Uttar Pradesh',
                'verification_level': 'verified'
            },
            'aap.org': {
                'name': 'Aam Aadmi Party',
                'short_name': 'AAP',
                'state': 'Delhi',
                'verification_level': 'verified'
            },
            'tdp.org': {
                'name': 'Telugu Desam Party',
                'short_name': 'TDP',
                'state': 'Andhra Pradesh',
                'verification_level': 'verified'
            },
            'ysrcp.org': {
                'name': 'YSR Congress Party',
                'short_name': 'YSRCP',
                'state': 'Andhra Pradesh',
                'verification_level': 'verified'
            },
            'jdu.org': {
                'name': 'Janata Dal (United)',
                'short_name': 'JD(U)',
                'state': 'Bihar',
                'verification_level': 'verified'
            },
            'rjd.org': {
                'name': 'Rashtriya Janata Dal',
                'short_name': 'RJD',
                'state': 'Bihar',
                'verification_level': 'verified'
            },
            'lsp.org': {
                'name': 'Lok Janshakti Party',
                'short_name': 'LJP',
                'state': 'Bihar',
                'verification_level': 'verified'
            }
        }
    
    def verify_party_email(self, email: str) -> Dict[str, Any]:
        """Verify if email belongs to a political party"""
        try:
            if not email or '@' not in email:
                return {
                    'is_verified': False,
                    'error': 'Invalid email format',
                    'verification_type': 'political_party'
                }
            
            domain = email.split('@')[1].lower()
            
            # Check if domain is in verified party domains
            is_party_email = domain in self.party_domains
            party_info = self.party_map.get(domain, {})
            
            # Additional validation for party admin emails
            if is_party_email:
                # Check for common admin patterns
                username = email.split('@')[0].lower()
                is_admin_email = self._is_admin_email(username)
                
                return {
                    'is_verified': True,
                    'party_name': party_info.get('name', 'Unknown Party'),
                    'party_short_name': party_info.get('short_name', ''),
                    'party_state': party_info.get('state', ''),
                    'domain': domain,
                    'verification_type': 'political_party',
                    'is_admin_email': is_admin_email,
                    'verification_level': party_info.get('verification_level', 'verified'),
                    'party_info': party_info
                }
            else:
                return {
                    'is_verified': False,
                    'error': 'Email domain not recognized as political party',
                    'domain': domain,
                    'verification_type': 'political_party',
                    'suggested_domains': self._get_suggested_domains(domain)
                }
                
        except Exception as e:
            logger.error(f"Party email verification error: {e}")
            return {
                'is_verified': False,
                'error': 'Verification failed',
                'details': str(e),
                'verification_type': 'political_party'
            }
    
    def _is_admin_email(self, username: str) -> bool:
        """Check if username suggests admin role"""
        admin_patterns = [
            'admin', 'administrator', 'manager', 'coordinator',
            'secretary', 'president', 'chairman', 'leader',
            'official', 'head', 'director', 'chief'
        ]
        
        username_lower = username.lower()
        return any(pattern in username_lower for pattern in admin_patterns)
    
    def _get_suggested_domains(self, domain: str) -> List[str]:
        """Get suggested party domains based on partial match"""
        suggestions = []
        domain_parts = domain.split('.')
        
        for party_domain in self.party_domains:
            party_parts = party_domain.split('.')
            if domain_parts[0] == party_parts[0]:
                suggestions.append(party_domain)
        
        return suggestions[:3]  # Return top 3 suggestions
    
    def get_party_info(self, domain: str) -> Dict[str, Any]:
        """Get detailed party information"""
        return self.party_map.get(domain, {})
    
    def get_all_parties(self) -> List[Dict[str, Any]]:
        """Get list of all verified political parties"""
        parties = []
        for domain, info in self.party_map.items():
            parties.append({
                'domain': domain,
                **info
            })
        return parties
    
    def add_custom_party(self, domain: str, party_info: Dict[str, Any]) -> bool:
        """Add custom political party domain"""
        try:
            if domain not in self.party_domains:
                self.party_domains.append(domain)
                self.party_map[domain] = {
                    'name': party_info.get('name', 'Custom Party'),
                    'short_name': party_info.get('short_name', ''),
                    'state': party_info.get('state', ''),
                    'verification_level': 'custom'
                }
                return True
            return False
        except Exception as e:
            logger.error(f"Error adding custom party: {e}")
            return False
    
    def validate_party_admin_credentials(self, email: str, party_name: str = None) -> Dict[str, Any]:
        """Validate party admin credentials"""
        verification_result = self.verify_party_email(email)
        
        if not verification_result['is_verified']:
            return verification_result
        
        # Additional validation for party admin
        if party_name:
            expected_party = verification_result.get('party_name', '')
            if party_name.lower() not in expected_party.lower():
                return {
                    'is_verified': False,
                    'error': 'Party name mismatch',
                    'expected_party': expected_party,
                    'provided_party': party_name
                }
        
        return {
            **verification_result,
            'admin_verification': 'approved',
            'permissions': ['create_events', 'manage_volunteers', 'view_analytics']
        }
