from typing import List, Dict, Any
from datetime import datetime, timedelta
import random
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class AutoMatcher:
    def __init__(self):
        self.matching_criteria = {
            'location': 0.4,      # 40% weight
            'availability': 0.3,  # 30% weight
            'skills': 0.2,        # 20% weight
            'rating': 0.1         # 10% weight
        }
        
        self.match_score_threshold = current_app.config.get('MATCH_SCORE_THRESHOLD', 0.7)
        self.max_volunteers_per_event = current_app.config.get('MAX_VOLUNTEERS_PER_EVENT', 5)
        self.location_radius_km = current_app.config.get('LOCATION_RADIUS_KM', 10.0)
    
    def match_volunteers_to_events(self, events: List[Dict], 
                                  volunteers: List[Dict]) -> Dict[str, List[Dict]]:
        """Match volunteers to events based on criteria"""
        try:
            matches = {}
            
            for event in events:
                if event.get('status') != 'upcoming':
                    continue
                    
                event_matches = []
                event_location = event.get('location', '')
                event_date = event.get('event_date')
                event_requirements = event.get('requirements', [])
                
                for volunteer in volunteers:
                    if volunteer.get('status') != 'approved':
                        continue
                        
                    # Check availability
                    if not self.is_volunteer_available(volunteer, event_date):
                        continue
                    
                    # Calculate match score
                    score = self.calculate_match_score(event, volunteer)
                    
                    if score >= self.match_score_threshold:
                        event_matches.append({
                            'volunteer_id': volunteer.get('id'),
                            'volunteer_uuid': volunteer.get('uuid'),
                            'volunteer_name': volunteer.get('name'),
                            'volunteer_email': volunteer.get('email'),
                            'volunteer_phone': volunteer.get('phone'),
                            'volunteer_location': volunteer.get('location'),
                            'score': score,
                            'match_reasons': self.get_match_reasons(event, volunteer, score)
                        })
                
                # Sort by score and take top matches
                event_matches.sort(key=lambda x: x['score'], reverse=True)
                matches[event.get('id')] = event_matches[:self.max_volunteers_per_event]
            
            logger.info(f"Auto matching completed: {len(matches)} events matched")
            return matches
            
        except Exception as e:
            logger.error(f"Auto matching error: {e}")
            return {}
    
    def calculate_match_score(self, event: Dict, volunteer: Dict) -> float:
        """Calculate match score between event and volunteer"""
        try:
            score = 0.0
            
            # Location matching (40%)
            location_score = self.calculate_location_score(event, volunteer)
            score += self.matching_criteria['location'] * location_score
            
            # Availability matching (30%)
            availability_score = self.calculate_availability_score(event, volunteer)
            score += self.matching_criteria['availability'] * availability_score
            
            # Skills matching (20%)
            skills_score = self.calculate_skills_score(event, volunteer)
            score += self.matching_criteria['skills'] * skills_score
            
            # Rating matching (10%)
            rating_score = self.calculate_rating_score(volunteer)
            score += self.matching_criteria['rating'] * rating_score
            
            return round(score, 3)
            
        except Exception as e:
            logger.error(f"Score calculation error: {e}")
            return 0.0
    
    def calculate_location_score(self, event: Dict, volunteer: Dict) -> float:
        """Calculate location-based match score"""
        try:
            event_location = event.get('location', '').lower()
            volunteer_location = volunteer.get('location', '').lower()
            
            # Exact location match
            if event_location == volunteer_location:
                return 1.0
            
            # Same city match
            event_city = event_location.split(',')[0].strip()
            volunteer_city = volunteer_location.split(',')[0].strip()
            
            if event_city == volunteer_city:
                return 0.8
            
            # Same state match
            event_state = self.extract_state(event_location)
            volunteer_state = self.extract_state(volunteer_location)
            
            if event_state and volunteer_state and event_state == volunteer_state:
                return 0.6
            
            # Nearby location (would integrate with Google Maps API)
            if self.is_nearby_location(event_location, volunteer_location):
                return 0.4
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Location score calculation error: {e}")
            return 0.0
    
    def calculate_availability_score(self, event: Dict, volunteer: Dict) -> float:
        """Calculate availability-based match score"""
        try:
            event_date = event.get('event_date')
            
            if not event_date:
                return 0.0
            
            # Check if volunteer is available on event date
            if self.is_volunteer_available(volunteer, event_date):
                return 1.0
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Availability score calculation error: {e}")
            return 0.0
    
    def calculate_skills_score(self, event: Dict, volunteer: Dict) -> float:
        """Calculate skills-based match score"""
        try:
            event_requirements = event.get('requirements', [])
            volunteer_skills = volunteer.get('skills', [])
            
            if not event_requirements:
                return 0.5  # Neutral score if no requirements
            
            if not volunteer_skills:
                return 0.0
            
            # Calculate skill match percentage
            matched_skills = 0
            total_required_skills = len(event_requirements)
            
            for requirement in event_requirements:
                required_skill = requirement.get('required_skill', '').lower()
                min_proficiency = requirement.get('min_proficiency', 1)
                
                for skill in volunteer_skills:
                    skill_name = skill.get('skill_name', '').lower()
                    proficiency = skill.get('proficiency_level', 1)
                    
                    if skill_name == required_skill and proficiency >= min_proficiency:
                        matched_skills += 1
                        break
            
            if total_required_skills > 0:
                return matched_skills / total_required_skills
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Skills score calculation error: {e}")
            return 0.0
    
    def calculate_rating_score(self, volunteer: Dict) -> float:
        """Calculate rating-based match score"""
        try:
            # This would be based on volunteer's past performance
            # For now, return a default score
            rating = volunteer.get('rating', 3.0)  # Default 3.0 rating
            return min(rating / 5.0, 1.0)  # Normalize to 0-1
            
        except Exception as e:
            logger.error(f"Rating score calculation error: {e}")
            return 0.5  # Neutral score
    
    def is_volunteer_available(self, volunteer: Dict, event_date: str) -> bool:
        """Check if volunteer is available on event date"""
        try:
            # Check existing registrations
            existing_registrations = volunteer.get('registrations', [])
            
            for registration in existing_registrations:
                registration_date = registration.get('event_date')
                if registration_date == event_date:
                    return False
            
            # Check volunteer's availability preferences
            availability_preferences = volunteer.get('availability_preferences', {})
            day_of_week = datetime.strptime(event_date, '%Y-%m-%d').strftime('%A').lower()
            
            if day_of_week in availability_preferences:
                return availability_preferences[day_of_week]
            
            return True  # Default to available
            
        except Exception as e:
            logger.error(f"Availability check error: {e}")
            return True
    
    def is_nearby_location(self, location1: str, location2: str) -> bool:
        """Check if locations are nearby (simplified)"""
        try:
            # This would integrate with Google Maps API for actual distance calculation
            # For now, use simple string matching
            
            location1_parts = location1.lower().split(',')
            location2_parts = location2.lower().split(',')
            
            # Check if they share any location component
            for part1 in location1_parts:
                for part2 in location2_parts:
                    if part1.strip() == part2.strip() and len(part1.strip()) > 2:
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Nearby location check error: {e}")
            return False
    
    def extract_state(self, location: str) -> str:
        """Extract state from location string"""
        try:
            parts = location.split(',')
            for part in parts:
                part = part.strip().lower()
                # Common state names
                states = ['tamil nadu', 'karnataka', 'maharashtra', 'delhi', 'kerala', 
                         'andhra pradesh', 'telangana', 'gujarat', 'rajasthan', 'punjab']
                if part in states:
                    return part
            return None
        except Exception:
            return None
    
    def get_match_reasons(self, event: Dict, volunteer: Dict, score: float) -> List[str]:
        """Get reasons for the match"""
        reasons = []
        
        # Location reason
        event_location = event.get('location', '').lower()
        volunteer_location = volunteer.get('location', '').lower()
        
        if event_location == volunteer_location:
            reasons.append("Same location")
        elif self.is_nearby_location(event_location, volunteer_location):
            reasons.append("Nearby location")
        
        # Skills reason
        event_requirements = event.get('requirements', [])
        volunteer_skills = volunteer.get('skills', [])
        
        if event_requirements and volunteer_skills:
            matched_skills = []
            for requirement in event_requirements:
                required_skill = requirement.get('required_skill', '').lower()
                for skill in volunteer_skills:
                    if skill.get('skill_name', '').lower() == required_skill:
                        matched_skills.append(required_skill)
            
            if matched_skills:
                reasons.append(f"Skills match: {', '.join(matched_skills)}")
        
        # Availability reason
        if self.is_volunteer_available(volunteer, event.get('event_date')):
            reasons.append("Available on event date")
        
        # High score reason
        if score >= 0.9:
            reasons.append("Excellent match")
        elif score >= 0.8:
            reasons.append("Very good match")
        elif score >= 0.7:
            reasons.append("Good match")
        
        return reasons
    
    def auto_assign_volunteers(self, event_id: str, matches: List[Dict]) -> Dict[str, Any]:
        """Auto assign volunteers to event"""
        try:
            assigned_volunteers = []
            
            for match in matches:
                if match['score'] >= 0.8:  # High confidence threshold for auto-assignment
                    assigned_volunteers.append({
                        'volunteer_id': match['volunteer_id'],
                        'volunteer_name': match['volunteer_name'],
                        'score': match['score'],
                        'auto_assigned': True
                    })
            
            logger.info(f"Auto assigned {len(assigned_volunteers)} volunteers to event {event_id}")
            
            return {
                'success': True,
                'assigned_volunteers': assigned_volunteers,
                'count': len(assigned_volunteers)
            }
            
        except Exception as e:
            logger.error(f"Auto assignment error: {e}")
            return {
                'success': False,
                'error': 'Failed to auto assign volunteers',
                'details': str(e)
            }
    
    def get_volunteer_recommendations(self, event: Dict, limit: int = 10) -> List[Dict]:
        """Get volunteer recommendations for an event"""
        try:
            # This would query the database for volunteers
            # For now, return mock data
            recommendations = []
            
            # Mock volunteer data
            mock_volunteers = [
                {
                    'id': 1,
                    'name': 'John Doe',
                    'location': 'Chennai, Tamil Nadu',
                    'skills': [{'skill_name': 'Event Management', 'proficiency_level': 4}],
                    'rating': 4.5
                },
                {
                    'id': 2,
                    'name': 'Jane Smith',
                    'location': 'Chennai, Tamil Nadu',
                    'skills': [{'skill_name': 'Crowd Management', 'proficiency_level': 3}],
                    'rating': 4.2
                }
            ]
            
            for volunteer in mock_volunteers:
                score = self.calculate_match_score(event, volunteer)
                if score >= self.match_score_threshold:
                    recommendations.append({
                        'volunteer': volunteer,
                        'score': score,
                        'match_reasons': self.get_match_reasons(event, volunteer, score)
                    })
            
            # Sort by score and limit results
            recommendations.sort(key=lambda x: x['score'], reverse=True)
            return recommendations[:limit]
            
        except Exception as e:
            logger.error(f"Volunteer recommendations error: {e}")
            return []
