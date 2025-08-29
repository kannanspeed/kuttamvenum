import googlemaps
from typing import Dict, Any, List, Tuple, Optional
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class GoogleMapsService:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or current_app.config.get('GOOGLE_MAPS_API_KEY')
        if self.api_key:
            self.gmaps = googlemaps.Client(key=self.api_key)
        else:
            self.gmaps = None
            logger.warning("Google Maps API key not configured")
    
    def geocode_address(self, address: str) -> Dict[str, Any]:
        """Convert address to coordinates"""
        try:
            if not self.gmaps:
                return {
                    'success': False,
                    'error': 'Google Maps API not configured'
                }
            
            result = self.gmaps.geocode(address)
            
            if result:
                location = result[0]['geometry']['location']
                formatted_address = result[0]['formatted_address']
                
                # Extract address components
                address_components = result[0].get('address_components', [])
                components = {}
                
                for component in address_components:
                    types = component['types']
                    if 'locality' in types:
                        components['city'] = component['long_name']
                    elif 'administrative_area_level_1' in types:
                        components['state'] = component['long_name']
                    elif 'country' in types:
                        components['country'] = component['long_name']
                    elif 'postal_code' in types:
                        components['postal_code'] = component['long_name']
                
                return {
                    'success': True,
                    'latitude': location['lat'],
                    'longitude': location['lng'],
                    'formatted_address': formatted_address,
                    'address_components': components,
                    'raw_data': result[0]
                }
            else:
                return {
                    'success': False,
                    'error': 'Address not found'
                }
                
        except Exception as e:
            logger.error(f"Geocoding error: {e}")
            return {
                'success': False,
                'error': 'Geocoding failed',
                'details': str(e)
            }
    
    def reverse_geocode(self, latitude: float, longitude: float) -> Dict[str, Any]:
        """Convert coordinates to address"""
        try:
            if not self.gmaps:
                return {
                    'success': False,
                    'error': 'Google Maps API not configured'
                }
            
            result = self.gmaps.reverse_geocode((latitude, longitude))
            
            if result:
                formatted_address = result[0]['formatted_address']
                
                # Extract address components
                address_components = result[0].get('address_components', [])
                components = {}
                
                for component in address_components:
                    types = component['types']
                    if 'locality' in types:
                        components['city'] = component['long_name']
                    elif 'administrative_area_level_1' in types:
                        components['state'] = component['long_name']
                    elif 'country' in types:
                        components['country'] = component['long_name']
                    elif 'postal_code' in types:
                        components['postal_code'] = component['long_name']
                
                return {
                    'success': True,
                    'formatted_address': formatted_address,
                    'address_components': components,
                    'raw_data': result[0]
                }
            else:
                return {
                    'success': False,
                    'error': 'Location not found'
                }
                
        except Exception as e:
            logger.error(f"Reverse geocoding error: {e}")
            return {
                'success': False,
                'error': 'Reverse geocoding failed',
                'details': str(e)
            }
    
    def calculate_distance(self, origin: Tuple[float, float], 
                          destination: Tuple[float, float], 
                          mode: str = "driving") -> Dict[str, Any]:
        """Calculate distance between two points"""
        try:
            if not self.gmaps:
                return {
                    'success': False,
                    'error': 'Google Maps API not configured'
                }
            
            result = self.gmaps.distance_matrix(origin, destination, mode=mode)
            
            if result['rows'][0]['elements'][0]['status'] == 'OK':
                element = result['rows'][0]['elements'][0]
                
                return {
                    'success': True,
                    'distance_km': element['distance']['value'] / 1000,
                    'distance_meters': element['distance']['value'],
                    'duration_seconds': element['duration']['value'],
                    'duration_text': element['duration']['text'],
                    'distance_text': element['distance']['text'],
                    'mode': mode
                }
            else:
                return {
                    'success': False,
                    'error': 'Distance calculation failed',
                    'status': result['rows'][0]['elements'][0]['status']
                }
                
        except Exception as e:
            logger.error(f"Distance calculation error: {e}")
            return {
                'success': False,
                'error': 'Distance calculation failed',
                'details': str(e)
            }
    
    def find_nearby_places(self, location: Tuple[float, float], 
                          radius: int = 5000, place_type: str = None) -> Dict[str, Any]:
        """Find nearby places"""
        try:
            if not self.gmaps:
                return {
                    'success': False,
                    'error': 'Google Maps API not configured'
                }
            
            places_result = self.gmaps.places_nearby(
                location=location,
                radius=radius,
                type=place_type
            )
            
            places = []
            for place in places_result.get('results', []):
                places.append({
                    'place_id': place['place_id'],
                    'name': place['name'],
                    'location': place['geometry']['location'],
                    'rating': place.get('rating'),
                    'vicinity': place.get('vicinity'),
                    'types': place.get('types', [])
                })
            
            return {
                'success': True,
                'places': places,
                'count': len(places),
                'next_page_token': places_result.get('next_page_token')
            }
            
        except Exception as e:
            logger.error(f"Nearby places search error: {e}")
            return {
                'success': False,
                'error': 'Nearby places search failed',
                'details': str(e)
            }
    
    def create_event_map(self, events: List[Dict]) -> Dict[str, Any]:
        """Create map with event locations"""
        try:
            if not self.api_key:
                return {
                    'success': False,
                    'error': 'Google Maps API key not configured'
                }
            
            # Generate static map URL with event markers
            markers = []
            center_lat = 0
            center_lng = 0
            valid_events = 0
            
            for event in events:
                if event.get('latitude') and event.get('longitude'):
                    lat = event['latitude']
                    lng = event['longitude']
                    markers.append(f"markers=color:red|label:{event.get('id', 'E')}|{lat},{lng}")
                    center_lat += lat
                    center_lng += lng
                    valid_events += 1
            
            if valid_events == 0:
                return {
                    'success': False,
                    'error': 'No events with valid coordinates'
                }
            
            # Calculate center point
            center_lat /= valid_events
            center_lng /= valid_events
            
            # Build map URL
            map_url = f"https://maps.googleapis.com/maps/api/staticmap?"
            map_url += f"center={center_lat},{center_lng}&zoom=10&size=600x400&maptype=roadmap"
            map_url += f"&{'&'.join(markers)}"
            map_url += f"&key={self.api_key}"
            
            return {
                'success': True,
                'map_url': map_url,
                'center_lat': center_lat,
                'center_lng': center_lng,
                'event_count': valid_events
            }
            
        except Exception as e:
            logger.error(f"Event map creation error: {e}")
            return {
                'success': False,
                'error': 'Failed to create event map',
                'details': str(e)
            }
    
    def create_volunteer_map(self, volunteers: List[Dict]) -> Dict[str, Any]:
        """Create map with volunteer locations"""
        try:
            if not self.api_key:
                return {
                    'success': False,
                    'error': 'Google Maps API key not configured'
                }
            
            # Generate static map URL with volunteer markers
            markers = []
            center_lat = 0
            center_lng = 0
            valid_volunteers = 0
            
            for volunteer in volunteers:
                if volunteer.get('latitude') and volunteer.get('longitude'):
                    lat = volunteer['latitude']
                    lng = volunteer['longitude']
                    markers.append(f"markers=color:blue|label:{volunteer.get('id', 'V')}|{lat},{lng}")
                    center_lat += lat
                    center_lng += lng
                    valid_volunteers += 1
            
            if valid_volunteers == 0:
                return {
                    'success': False,
                    'error': 'No volunteers with valid coordinates'
                }
            
            # Calculate center point
            center_lat /= valid_volunteers
            center_lng /= valid_volunteers
            
            # Build map URL
            map_url = f"https://maps.googleapis.com/maps/api/staticmap?"
            map_url += f"center={center_lat},{center_lng}&zoom=10&size=600x400&maptype=roadmap"
            map_url += f"&{'&'.join(markers)}"
            map_url += f"&key={self.api_key}"
            
            return {
                'success': True,
                'map_url': map_url,
                'center_lat': center_lat,
                'center_lng': center_lng,
                'volunteer_count': valid_volunteers
            }
            
        except Exception as e:
            logger.error(f"Volunteer map creation error: {e}")
            return {
                'success': False,
                'error': 'Failed to create volunteer map',
                'details': str(e)
            }
    
    def find_nearby_volunteers(self, event_location: Tuple[float, float], 
                              radius_km: float = 10.0) -> Dict[str, Any]:
        """Find volunteers within radius of event"""
        try:
            if not self.gmaps:
                return {
                    'success': False,
                    'error': 'Google Maps API not configured'
                }
            
            # This would query your database for volunteers and filter by distance
            # For now, return mock data
            nearby_volunteers = [
                {
                    'id': 1,
                    'name': 'John Doe',
                    'location': 'Chennai, Tamil Nadu',
                    'latitude': 13.0827,
                    'longitude': 80.2707,
                    'distance_km': 2.5
                },
                {
                    'id': 2,
                    'name': 'Jane Smith',
                    'location': 'Chennai, Tamil Nadu',
                    'latitude': 13.0827,
                    'longitude': 80.2707,
                    'distance_km': 5.1
                }
            ]
            
            return {
                'success': True,
                'volunteers': nearby_volunteers,
                'count': len(nearby_volunteers),
                'radius_km': radius_km
            }
            
        except Exception as e:
            logger.error(f"Nearby volunteers search error: {e}")
            return {
                'success': False,
                'error': 'Nearby volunteers search failed',
                'details': str(e)
            }
    
    def get_route_directions(self, origin: Tuple[float, float], 
                           destination: Tuple[float, float], 
                           mode: str = "driving") -> Dict[str, Any]:
        """Get route directions between two points"""
        try:
            if not self.gmaps:
                return {
                    'success': False,
                    'error': 'Google Maps API not configured'
                }
            
            directions = self.gmaps.directions(origin, destination, mode=mode)
            
            if directions:
                route = directions[0]
                leg = route['legs'][0]
                
                steps = []
                for step in leg['steps']:
                    steps.append({
                        'instruction': step['html_instructions'],
                        'distance': step['distance']['text'],
                        'duration': step['duration']['text']
                    })
                
                return {
                    'success': True,
                    'distance': leg['distance']['text'],
                    'duration': leg['duration']['text'],
                    'start_address': leg['start_address'],
                    'end_address': leg['end_address'],
                    'steps': steps,
                    'polyline': route['overview_polyline']['points']
                }
            else:
                return {
                    'success': False,
                    'error': 'No route found'
                }
                
        except Exception as e:
            logger.error(f"Route directions error: {e}")
            return {
                'success': False,
                'error': 'Route directions failed',
                'details': str(e)
            }
    
    def validate_coordinates(self, latitude: float, longitude: float) -> bool:
        """Validate if coordinates are within valid range"""
        try:
            return -90 <= latitude <= 90 and -180 <= longitude <= 180
        except Exception:
            return False
    
    def calculate_bounding_box(self, locations: List[Tuple[float, float]]) -> Dict[str, float]:
        """Calculate bounding box for multiple locations"""
        try:
            if not locations:
                return {}
            
            min_lat = max_lat = locations[0][0]
            min_lng = max_lng = locations[0][1]
            
            for lat, lng in locations:
                min_lat = min(min_lat, lat)
                max_lat = max(max_lat, lat)
                min_lng = min(min_lng, lng)
                max_lng = max(max_lng, lng)
            
            return {
                'min_lat': min_lat,
                'max_lat': max_lat,
                'min_lng': min_lng,
                'max_lng': max_lng,
                'center_lat': (min_lat + max_lat) / 2,
                'center_lng': (min_lng + max_lng) / 2
            }
            
        except Exception as e:
            logger.error(f"Bounding box calculation error: {e}")
            return {}
