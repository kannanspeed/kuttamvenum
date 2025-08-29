import requests
import json
import base64
from typing import Dict, Any, Optional
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class HypervergeKYC:
    def __init__(self, api_key: str = None, api_secret: str = None):
        self.api_key = api_key or current_app.config.get('HYPERVERGE_API_KEY')
        self.api_secret = api_secret or current_app.config.get('HYPERVERGE_API_SECRET')
        self.base_url = "https://ind-docs.hyperverge.co/v4"
    
    def verify_aadhaar(self, front_image_path: str, back_image_path: str) -> Dict[str, Any]:
        """Verify Aadhaar card using Hyperverge API"""
        try:
            # Read and encode images
            front_image = self._encode_image(front_image_path)
            back_image = self._encode_image(back_image_path)
            
            url = f"{self.base_url}/readAadhaar"
            
            payload = {
                "image": front_image,
                "image2": back_image
            }
            
            headers = {
                "appId": self.api_key,
                "appKey": self.api_secret,
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Aadhaar verification result: {result}")
            
            return self._parse_aadhaar_result(result)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Hyperverge API error: {e}")
            return {
                'success': False,
                'error': 'API request failed',
                'details': str(e)
            }
        except Exception as e:
            logger.error(f"Aadhaar verification error: {e}")
            return {
                'success': False,
                'error': 'Verification failed',
                'details': str(e)
            }
    
    def verify_face_match(self, aadhaar_photo_path: str, selfie_path: str) -> Dict[str, Any]:
        """Verify face match between Aadhaar and selfie"""
        try:
            # Read and encode images
            aadhaar_photo = self._encode_image(aadhaar_photo_path)
            selfie = self._encode_image(selfie_path)
            
            url = f"{self.base_url}/faceCompare"
            
            payload = {
                "image1": aadhaar_photo,
                "image2": selfie
            }
            
            headers = {
                "appId": self.api_key,
                "appKey": self.api_secret,
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Face match result: {result}")
            
            return self._parse_face_match_result(result)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Hyperverge face match API error: {e}")
            return {
                'success': False,
                'error': 'API request failed',
                'details': str(e)
            }
        except Exception as e:
            logger.error(f"Face match verification error: {e}")
            return {
                'success': False,
                'error': 'Face match failed',
                'details': str(e)
            }
    
    def _encode_image(self, image_path: str) -> str:
        """Encode image to base64"""
        try:
            with open(image_path, 'rb') as image_file:
                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                return encoded_string
        except Exception as e:
            logger.error(f"Image encoding error: {e}")
            raise
    
    def _parse_aadhaar_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Aadhaar verification result"""
        try:
            if result.get('status') == 'success':
                data = result.get('data', {})
                return {
                    'success': True,
                    'aadhaar_number': data.get('aadhaar_number'),
                    'name': data.get('name'),
                    'date_of_birth': data.get('date_of_birth'),
                    'gender': data.get('gender'),
                    'address': data.get('address'),
                    'confidence_score': data.get('confidence_score', 0),
                    'is_valid': data.get('is_valid', False),
                    'raw_data': data
                }
            else:
                return {
                    'success': False,
                    'error': result.get('message', 'Verification failed'),
                    'details': result
                }
        except Exception as e:
            logger.error(f"Error parsing Aadhaar result: {e}")
            return {
                'success': False,
                'error': 'Failed to parse result',
                'details': str(e)
            }
    
    def _parse_face_match_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Parse face match verification result"""
        try:
            if result.get('status') == 'success':
                data = result.get('data', {})
                return {
                    'success': True,
                    'match_score': data.get('match_score', 0),
                    'is_match': data.get('is_match', False),
                    'confidence': data.get('confidence', 0),
                    'raw_data': data
                }
            else:
                return {
                    'success': False,
                    'error': result.get('message', 'Face match failed'),
                    'details': result
                }
        except Exception as e:
            logger.error(f"Error parsing face match result: {e}")
            return {
                'success': False,
                'error': 'Failed to parse face match result',
                'details': str(e)
            }
    
    def verify_documents(self, front_image_path: str, back_image_path: str, 
                        selfie_path: str) -> Dict[str, Any]:
        """Complete document verification process"""
        try:
            # Step 1: Verify Aadhaar
            aadhaar_result = self.verify_aadhaar(front_image_path, back_image_path)
            
            if not aadhaar_result['success']:
                return aadhaar_result
            
            # Step 2: Verify face match
            face_result = self.verify_face_match(front_image_path, selfie_path)
            
            if not face_result['success']:
                return face_result
            
            # Step 3: Calculate overall verification score
            aadhaar_score = aadhaar_result.get('confidence_score', 0)
            face_score = face_result.get('match_score', 0)
            
            overall_score = (aadhaar_score + face_score) / 2
            
            return {
                'success': True,
                'aadhaar_verification': aadhaar_result,
                'face_verification': face_result,
                'overall_score': overall_score,
                'is_verified': overall_score >= 0.7 and aadhaar_result.get('is_valid', False)
            }
            
        except Exception as e:
            logger.error(f"Complete verification error: {e}")
            return {
                'success': False,
                'error': 'Complete verification failed',
                'details': str(e)
            }
