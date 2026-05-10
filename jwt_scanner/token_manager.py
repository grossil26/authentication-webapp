#!/usr/bin/env python3
"""
Token Manager Module - Handles JWT token lifecycle management
Separate from main scanner for better code organization
"""

import time
import json
import base64
from typing import Optional, Dict, Any
from datetime import datetime


class TokenManager:
    """
    Manages JWT tokens with automatic refresh capability.
    Handles token extraction, expiry monitoring, and automatic renewal.
    """
    
    def __init__(self, scanner_callback=None):
        """
        Initialize the token manager
        
        Args:
            scanner_callback: Reference to the scanner's authentication method
                            Will be called when token needs refresh
        """
        self.current_token = None
        self.expiry_time = None
        self.token_obtained_time = None
        self.refresh_buffer_seconds = 30  # Refresh 30 seconds before expiry
        self.scanner_callback = scanner_callback
        self.token_metadata = {}
        
    def parse_jwt_payload(self, token: str) -> Optional[Dict]:
        """
        Extract and decode the payload from a JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded payload as dictionary, or None if invalid
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode the payload (second part)
            payload_b64 = parts[1]
            
            # Add padding if needed for base64 decoding
            padding_needed = 4 - (len(payload_b64) % 4)
            if padding_needed != 4:
                payload_b64 += '=' * padding_needed
            
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)
            
            return payload
            
        except Exception as e:
            print(f"[TokenManager] Failed to parse JWT: {e}")
            return None
    
    def extract_expiry(self, token: str) -> Optional[int]:
        """
        Extract expiration time from JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            Unix timestamp of expiration, or None if not found
        """
        payload = self.parse_jwt_payload(token)
        if payload and 'exp' in payload:
            return payload['exp']
        return None
    
    def set_token(self, token: str) -> bool:
        """
        Set a new token and calculate its expiry
        
        Args:
            token: JWT token string
            
        Returns:
            True if token is valid, False otherwise
        """
        if not token or len(token.split('.')) != 3:
            return False
        
        self.current_token = token
        self.token_obtained_time = time.time()
        self.expiry_time = self.extract_expiry(token)
        
        # Store additional metadata
        payload = self.parse_jwt_payload(token)
        if payload:
            self.token_metadata = {
                'issuer': payload.get('iss', 'unknown'),
                'subject': payload.get('sub', 'unknown'),
                'issued_at': payload.get('iat', None),
                'has_expiry': 'exp' in payload
            }
        
        # Log token info (will be printed by scanner, but keep for direct use)
        if self.expiry_time:
            expires_in = self.expiry_time - self.token_obtained_time
            expires_minutes = expires_in / 60
            print(f"[TokenManager] Token set. Expires in {expires_minutes:.1f} minutes")
        else:
            print(f"[TokenManager] Token set. No expiry info available")
        
        return True
    
    def is_expired(self) -> bool:
        """
        Check if current token is expired or about to expire
        
        Returns:
            True if token needs refresh, False otherwise
        """
        if not self.current_token:
            return True
        
        if not self.expiry_time:
            # No expiry info - assume it's valid but log warning
            print("[TokenManager] Warning: Token has no expiry information")
            return False
        
        current_time = time.time()
        time_left = self.expiry_time - current_time
        
        # Check if token is already expired
        if time_left <= 0:
            print(f"[TokenManager] Token expired {abs(time_left):.0f} seconds ago")
            return True
        
        # Check if token is within refresh buffer
        if time_left < self.refresh_buffer_seconds:
            print(f"[TokenManager] Token expiring in {time_left:.0f} seconds - needs refresh")
            return True
        
        # Token is still valid
        if time_left < 60:
            print(f"[TokenManager] Token expires in {time_left:.0f} seconds")
        elif time_left < 300:
            print(f"[TokenManager] Token expires in {time_left/60:.1f} minutes")
        
        return False
    
    def refresh_token(self) -> bool:
        """
        Refresh the token by calling the authentication callback
        
        Returns:
            True if refresh successful, False otherwise
        """
        if not self.scanner_callback:
            print("[TokenManager] ERROR: No authentication callback provided")
            return False
        
        print(f"[TokenManager] Refreshing token at {datetime.now().strftime('%H:%M:%S')}")
        
        try:
            new_token = self.scanner_callback()
            
            if new_token and self.set_token(new_token):
                print(f"[TokenManager] Token refreshed successfully")
                return True
            else:
                print(f"[TokenManager] Failed to refresh token")
                return False
                
        except Exception as e:
            print(f"[TokenManager] Error during token refresh: {e}")
            return False
    
    def get_valid_token(self) -> Optional[str]:
        """
        Get a valid token, automatically refreshing if needed
        
        Returns:
            Valid token string, or None if cannot obtain
        """
        if self.is_expired():
            if not self.refresh_token():
                return None
        
        return self.current_token
    
    def get_token_info(self) -> Dict:
        """
        Get information about the current token
        
        Returns:
            Dictionary with token metadata
        """
        return {
            'has_token': self.current_token is not None,
            'token_expiry': self.expiry_time,
            'time_remaining': self.expiry_time - time.time() if self.expiry_time else None,
            'token_obtained': self.token_obtained_time,
            'metadata': self.token_metadata
        }
    
    def force_refresh(self) -> bool:
        """
        Force an immediate token refresh regardless of expiry
        
        Returns:
            True if refresh successful
        """
        print("[TokenManager] Forcing immediate token refresh")
        return self.refresh_token()
    
    def clear_token(self):
        """Clear the current token (force re-authentication on next use)"""
        self.current_token = None
        self.expiry_time = None
        self.token_obtained_time = None
        self.token_metadata = {}
        print("[TokenManager] Token cleared")


# For testing the token manager independently
if __name__ == "__main__":
    # Test the TokenManager class
    print("Testing TokenManager...")
    
    # Mock authentication function for testing
    def mock_authenticate():
        import jwt
        import datetime
        
        # Create a test token that expires in 60 seconds
        payload = {
            'sub': 'testuser',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60),
            'iat': datetime.datetime.utcnow()
        }
        secret = 'test_secret'
        token = jwt.encode(payload, secret, algorithm='HS256')
        return token
    
    # Create token manager with mock callback
    tm = TokenManager(scanner_callback=mock_authenticate)
    
    # Test getting a token
    token = tm.get_valid_token()
    print(f"Got token: {token[:50]}...")
    
    # Test token info
    info = tm.get_token_info()
    print(f"Token info: {info}")
    
    # Test expiry checking
    print(f"Is expired: {tm.is_expired()}")
