"""
Stateful Authentication Module.

This module handles dynamic login processes for web vulnerability scanning.
It navigates to a target URL, extracts hidden CSRF tokens, submits credentials,
and returns an active session object to be used by the main scanning engine.
"""

import requests
from bs4 import BeautifulSoup


class StatefulAuthentication:
    """
    Stateful Authentication Module for web vulnerability scanning.

    Args:
         url: Target login URL.
        user: Username to inject.
        password: Password to inject.
        success_string: Text in the response body indicating successful login.
        auth_type: Type of login mechanism. One of: form, basic, json.
        user_field: HTML name or JSON key for the username field.
        pass_field: HTML name or JSON key for the password field.
        csrf_field: HTML name attribute of the CSRF token input (form auth only).
    """
    def __init__(
        self,
        url: str,
        user: str,
        password: str,
        success_string: str,
        auth_type: str,
        user_field: str = None,
        pass_field: str = None,
        csrf_field: str = None,
    ):
        self.login_url = url
        self.username = user
        self.password = password
        self.success_string = success_string
        self.auth_type = auth_type
        self.user_field = user_field
        self.pass_field = pass_field
        self.csrf_field = csrf_field

    def __call__(self):
        """Execute the authentication flow."""
        active_session = self.authenticate()

        if active_session:
            print(f"Current Session Cookies: {active_session.cookies.get_dict()}")

        return active_session
    def authenticate(self):
        """Routes the authentication request to the correct strategy based on auth_type."""
        print(f"Initializing stateful session (Strategy: {self.auth_type.upper()})...")
        session = requests.Session()

        if self.auth_type == 'form':
            return self.do_form_login(session)
        elif self.auth_type == 'basic':
            return self.do_basic_login(session)
        elif self.auth_type == 'json':
            return self.do_json_login(session)
        else:
            print(f"ERROR: Unknown auth_type '{self.auth_type}'. Must be one of: form, basic, json.")
            return None

    def do_form_login(self, session):
        """Handles standard HTML forms with CSRF tokens.

        Args:
            session: A requests.Session object to use for the login request.

        Returns:
            requests.Session: An authenticated session if successful, or None if it fails.
        """
        print(f"Visiting {self.login_url} to extract the CSRF token...")

        try:
            response = session.get(self.login_url, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"FATAL: Could not reach the target URL ({self.login_url}).")
            print(f"Error details: {e}")
            return None

        soup = BeautifulSoup(response.text, 'html.parser')
        token_input = soup.find('input', {'name': self.csrf_field})

        if not token_input:
            print("Error: Could not find the CSRF token on the page!")
            return None

        csrf_token = token_input.get('value')
        print(f"Found hidden CSRF Token: {csrf_token}")

        login_data = {
            self.user_field: self.username,
            self.pass_field: self.password,
            self.csrf_field: csrf_token,
            'Login': 'Login'
        }

        print("Submitting login credentials and token...")
        try:
            login_response = session.post(self.login_url, data=login_data, timeout=10)
            login_response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"FATAL: Failed to submit login data.")
            return None

        if self.success_string in login_response.text:
            print("[SUCCESS] Form Authentication Successful! The session is active.")
            return session
        else:
            print("Authentication Failed. Success string not found.")
            return None

    def do_basic_login(self, session):
        """Handles HTTP Basic Authentication (browser pop-ups).

        Args:
            session: A requests.Session object to use for the login request.

        Returns:
            requests.Session: An authenticated session if successful, or None if it fails.
        """
        print(f"Attempting HTTP Basic Auth at {self.login_url}...")

        try:
            response = session.get(self.login_url, auth=(self.username, self.password), timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"FATAL: Basic Auth request failed.")
            print(f"Error details: {e}")
            return None

        if self.success_string in response.text:
            print("[SUCCESS] HTTP Basic Auth Successful! The session is active.")
            return session
        else:
            print("Basic Auth Failed. Success string not found.")
            return None

    def do_json_login(self, session):
        """Handles modern API authentication sending application/json.

        Args:
            session: A requests.Session object to use for the login request.

        Returns:
            requests.Session: An authenticated session if successful, or None if it fails.
        """
        print(f"Attempting JSON API Auth at {self.login_url}...")

        json_payload = {
            self.user_field: self.username,
            self.pass_field: self.password
        }

        try:
            response = session.post(self.login_url, json=json_payload, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"FATAL: JSON API Auth request failed.")
            print(f"Error details: {e}")
            return None

        if self.success_string in response.text:
            print("[SUCCESS] JSON API Auth Successful! The session is active.")
            return session
        else:
            print("JSON API Auth Failed. Success string not found.")
            return None