#!/usr/bin/env python3
"""
Stateful Authentication Module for DAST Scanner.

This module handles dynamic login processes for web vulnerability scanning.
It routes authentication requests based on the target's requirements (Form, Basic, JSON, Bearer),
extracts necessary tokens (like CSRF), and returns an authenticated requests.Session()
object and the extracted JSON Web Token (JWT) to be utilized by downstream vulnerability scanners.
"""

import re
import requests
from bs4 import BeautifulSoup
from typing import Optional, Tuple

# Simple relative import - assumes proper package structure
from ..jwt_scanner.scanner import JWTScanner


class AuthHandler:
    """
    Stateful Authentication Handler for web vulnerability scanning.

    Handles all authentication mechanisms and state management.
    Returns both an authenticated session and any extracted JWT token.

    Args:
        login_url: Target login URL.
        username: Username to inject.
        password: Password to inject.
        auth_type: Type of login mechanism. One of: form, basic, json, bearer.
        user_field: HTML name or JSON key for the username field (default: 'username').
        pass_field: HTML name or JSON key for the password field (default: 'password').
        csrf_field: HTML name attribute of the CSRF token input (form auth only, default: 'csrf').
        success_string: Text in the response body indicating successful login.
        token_fields: List of JSON fields that may contain JWT tokens.
        token: Pre-existing bearer token (bearer auth only).
        scan_mode: If True, runs JWT scanner after authentication (default: False).
        target: Target base URL for scanning (required if scan_mode=True).
        protected_endpoint: Protected endpoint requiring JWT (required if scan_mode=True).
        wordlist: Path to weak secrets dictionary.
        output: Output report file (default: 'jwt_scan_report.json').
        verbose: Enable verbose output (default: False).
        timeout: Request timeout in seconds (default: 10).
        max_secret_tests: Max secrets to test (default: 0 = all).
        jku_callback_server: Server URL for jku testing.
        public_key_file: PEM file or Base64 encoded public key.
        admin_endpoint: Protected endpoint for algorithm confusion (default: '/admin').
        target_user: User to impersonate (default: 'administrator').
        token_location: Where to send token - header, cookie, param, both (default: 'both').
    """
    def __init__(
        self,
        login_url: str = None,
        username: str = None,
        password: str = None,
        auth_type: str = None,
        user_field: str = 'username',
        pass_field: str = 'password',
        csrf_field: str = 'csrf',
        success_string: str = None,
        token_fields: str = 'token,access_token,jwt,id_token',
        token: str = None,
        scan_mode: bool = False,
        # Scanner arguments
        target: str = None,
        protected_endpoint: str = None,
        wordlist: str = '',
        output: str = 'jwt_scan_report.json',
        verbose: bool = False,
        timeout: int = 10,
        max_secret_tests: int = 0,
        jku_callback_server: str = '',
        public_key_file: str = None,
        admin_endpoint: str = '/admin',
        target_user: str = 'administrator',
        token_location: str = 'both',
    ):
        # Authentication parameters
        self.login_url = login_url
        self.username = username
        self.password = password
        self.auth_type = auth_type
        self.user_field = user_field
        self.pass_field = pass_field
        self.csrf_field = csrf_field
        self.success_string = success_string

        # Handle token_fields - could be string or list
        if isinstance(token_fields, str):
            self.token_fields = token_fields.split(',')
        else:
            self.token_fields = token_fields

        self.token = token
        self.session = None

        # Mode flag (set by main.py based on which command is called)
        self.scan_mode = scan_mode

        # Scanner parameters
        self.target = target
        self.protected_endpoint = protected_endpoint
        self.wordlist = wordlist
        self.output = output
        self.verbose = verbose
        self.timeout = timeout
        self.max_secret_tests = max_secret_tests
        self.jku_callback_server = jku_callback_server
        self.public_key_file = public_key_file
        self.admin_endpoint = admin_endpoint
        self.target_user = target_user
        self.token_location = token_location

    def __call__(self):
        """Execute the authentication flow."""
        mode_text = "AUTHENTICATION + JWT SCANNING" if self.scan_mode else "AUTHENTICATION ONLY"
        print("\n" + "="*70)
        print(f"RUNNING IN {mode_text} MODE")
        print(f"{'='*70}")

        # Validate required parameters for authentication
        if not self.auth_type:
            print("[ERROR] auth_type is required (form, basic, json, bearer)")
            return None, None

        if self.auth_type != 'bearer':
            if not self.login_url:
                print(f"[ERROR] login_url is required for {self.auth_type} authentication")
                return None, None
            if not self.username:
                print(f"[ERROR] username is required for {self.auth_type} authentication")
                return None, None
            if not self.password:
                print(f"[ERROR] password is required for {self.auth_type} authentication")
                return None, None

        print(f"\n[*] Initializing stateful session (Strategy: {self.auth_type.upper()})...")

        active_session, extracted_token = self.authenticate()

        if active_session:
            print(f"[*] Current Session Cookies: {active_session.cookies.get_dict()}")
            if extracted_token:
                print(f"[*] Extracted JWT Token: {extracted_token[:50]}...")

            # Only run scanner if in scan_mode
            if self.scan_mode:
                if self.target and self.protected_endpoint:
                    self._run_jwt_scanner(active_session, extracted_token)
                else:
                    print("\n[ERROR] Scan mode requires --target and --protected_endpoint")
                    print("[*] Please provide both parameters for JWT scanning")
                    print("[*] Example: --target https://example.com --protected_endpoint /admin")
            else:
                print("\n[*] Authentication completed successfully!")
                print("[*] Use 'jwt_scanner' command for full vulnerability scanning")

            return active_session, extracted_token
        else:
            print("\n[FAILED] Authentication failed!")
            return None, None

    def authenticate(self) -> Tuple[Optional[requests.Session], Optional[str]]:
        """Routes the authentication request to the correct strategy based on auth_type."""
        self.session = requests.Session()

        if self.auth_type == 'form':
            return self._do_form_login()
        elif self.auth_type == 'basic':
            return self._do_basic_login()
        elif self.auth_type == 'json':
            return self._do_json_login()
        elif self.auth_type == 'bearer':
            return self._do_bearer_login()
        else:
            print(f"[ERROR] Unknown auth_type '{self.auth_type}'. Must be one of: form, basic, json, bearer.")
            return None, None

    def _do_form_login(self) -> Tuple[Optional[requests.Session], Optional[str]]:
        """Handles standard HTML forms with CSRF tokens.

        Returns:
            Tuple[Optional[requests.Session], Optional[str]]: Authenticated session and extracted JWT token.
        """
        print(f"[*] Visiting {self.login_url} to extract the CSRF token...")

        try:
            resp = self.session.get(self.login_url, timeout=10)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"[FATAL] Could not reach the target URL ({self.login_url}).")
            print(f"[ERROR] Error details: {e}")
            return None, None

        soup = BeautifulSoup(resp.text, 'html.parser')
        token_input = soup.find('input', {'name': self.csrf_field})

        if not token_input:
            # Try alternative CSRF field names
            for csrf_name in ['csrf', 'csrf_token', 'csrfToken', '_csrf', 'csrfmiddlewaretoken']:
                token_input = soup.find('input', {'name': csrf_name})
                if token_input:
                    print(f"[*] Found CSRF with alternative name: {csrf_name}")
                    self.csrf_field = csrf_name
                    break

        if not token_input:
            print("[WARN] No CSRF token found, proceeding without it")
            csrf_token = None
        else:
            csrf_token = token_input.get('value')
            print(f"[+] Found hidden CSRF Token: {csrf_token[:20] if csrf_token else 'None'}...")

        login_data = {
            self.user_field: self.username,
            self.pass_field: self.password,
        }
        if csrf_token:
            login_data[self.csrf_field] = csrf_token
            login_data['Login'] = 'Login'

        print("[*] Submitting login credentials and token...")
        try:
            resp = self.session.post(self.login_url, data=login_data, timeout=10)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print("[FATAL] Failed to submit login data.")
            print(f"[ERROR] Error details: {e}")
            return None, None

        # Check for successful login
        if self.success_string and self.success_string not in resp.text:
            print("[ERROR] Authentication Failed. Success string not found.")
            return None, None

        print("[SUCCESS] Form Authentication Successful! The session is active.")

        # Extract JWT token if present
        token = self._extract_jwt_token(resp)
        if token and self._is_jwt_format(token):
            print("[+] JWT token also extracted from form login!")
            return self.session, token
        else:
            print("[INFO] No JWT token found (Cookie-based session established).")
            return self.session, None

    def _do_basic_login(self) -> Tuple[Optional[requests.Session], Optional[str]]:
        """Handles HTTP Basic Authentication (browser pop-ups).

        Returns:
            Tuple[Optional[requests.Session], Optional[str]]: Authenticated session and extracted JWT token.
        """
        print(f"[*] Attempting HTTP Basic Auth at {self.login_url}...")

        try:
            resp = self.session.get(
                self.login_url,
                auth=(self.username, self.password),
                timeout=10
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print("[FATAL] Basic Auth request failed.")
            print(f"[ERROR] Error details: {e}")
            return None, None

        # Check for successful login
        if self.success_string and self.success_string not in resp.text:
            print("[ERROR] Authentication Failed. Success string not found.")
            return None, None

        print("[SUCCESS] Basic Authentication Successful! The session is active.")

        # Extract JWT token if present
        token = self._extract_jwt_token(resp)
        if token and self._is_jwt_format(token):
            print("[+] JWT token also extracted from basic auth!")
            return self.session, token
        else:
            print("[INFO] No JWT token found (Stateless Basic Auth established).")
            return self.session, None

    def _do_json_login(self) -> Tuple[Optional[requests.Session], Optional[str]]:
        """Handles modern API authentication sending application/json.

        Returns:
            Tuple[Optional[requests.Session], Optional[str]]: Authenticated session and extracted JWT token.
        """
        print(f"[*] Attempting JSON API Auth at {self.login_url}...")

        json_payload = {
            self.user_field: self.username,
            self.pass_field: self.password
        }

        try:
            resp = self.session.post(
                self.login_url,
                json=json_payload,
                timeout=10
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print("[FATAL] JSON API Auth request failed.")
            print(f"[ERROR] Error details: {e}")
            return None, None

        # Check for successful login
        if self.success_string and self.success_string not in resp.text:
            print("[ERROR] Authentication Failed. Success string not found.")
            return None, None

        print("[SUCCESS] JSON Authentication Successful! The session is active.")

        # Extract JWT token if present
        token = self._extract_jwt_token(resp)
        if token and self._is_jwt_format(token):
            print("[+] JWT token also extracted from JSON response!")
            return self.session, token
        else:
            print("[INFO] No JWT token found (Cookie-based session established).")
            return self.session, None

    def _do_bearer_login(self) -> Tuple[Optional[requests.Session], Optional[str]]:
        """Handles pre-existing bearer token authentication.

        Returns:
            Tuple[Optional[requests.Session], Optional[str]]: Session with bearer token and the token itself.
        """
        print("[*] Using provided bearer token")

        if self.token and self._is_jwt_format(self.token):
            print("[SUCCESS] Valid JWT token provided")
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            return self.session, self.token
        else:
            print("[ERROR] Invalid or missing bearer token")
            print("[*] Please provide a valid JWT token with --token parameter")
            return None, None

    def _extract_jwt_token(self, response) -> Optional[str]:
        """Extract JWT token from response body, headers, or cookies."""
        # Try to extract from JSON response
        try:
            data = response.json()
            for field in self.token_fields:
                if field in data:
                    token = data[field]
                    if self._is_jwt_format(token):
                        return token
            if 'authentication' in data and 'token' in data['authentication']:
                token = data['authentication']['token']
                if self._is_jwt_format(token):
                    return token
            for value in data.values():
                if isinstance(value, dict) and 'token' in value:
                    token = value['token']
                    if self._is_jwt_format(token):
                        return token
        except Exception:
            pass

        # Try to extract from Authorization header
        if 'Authorization' in response.headers:
            auth_header = response.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                if self._is_jwt_format(token):
                    return token

        # Try to extract from cookies
        for cookie in self.session.cookies:
            if any(key in cookie.name.lower() for key in ['session', 'token', 'jwt', 'auth']):
                if self._is_jwt_format(cookie.value):
                    print(f"[*] Found JWT in session cookie: {cookie.name}")
                    return cookie.value

        # Try to extract from response text using regex
        matches = re.findall(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', response.text)
        if matches:
            return matches[0]

        return None

    @staticmethod
    def _is_jwt_format(token: str) -> bool:
        """Check if a string appears to be in JWT format."""
        if not token or not isinstance(token, str):
            return False
        parts = token.split('.')
        return len(parts) == 3 and all(len(p) > 0 for p in parts)

    def _run_jwt_scanner(self, session, jwt_token):
        """Run the JWT scanner with the authenticated session and token."""
        print("\n" + "="*70)
        print("STEP 2: LAUNCHING JWT SCANNER")
        print("="*70)

        try:
            # Import from jwt_scanner folder (already imported at top, but keeping for context)
            import inspect

            print("[+] Successfully imported JWTScanner")

            # Inspect the JWTScanner __init__ signature
            sig = inspect.signature(JWTScanner.__init__)
            print(f"[*] JWTScanner __init__ signature: {sig}")

            # Create a simple args object that JWTScanner expects
            class ScannerArgs:
                pass

            scanner_args = ScannerArgs()
            scanner_args.url = self.target
            scanner_args.protected_endpoint = self.protected_endpoint
            scanner_args.wordlist = self.wordlist
            scanner_args.output = self.output
            scanner_args.verbose = self.verbose
            scanner_args.timeout = self.timeout
            scanner_args.max_secret_tests = self.max_secret_tests
            scanner_args.jku_callback_server = self.jku_callback_server
            scanner_args.public_key_file = self.public_key_file
            scanner_args.admin_endpoint = self.admin_endpoint
            scanner_args.target_user = self.target_user
            scanner_args.token_location = self.token_location

            # Try different initialization patterns based on the signature
            params = list(sig.parameters.keys())

            if len(params) >= 2 and params[1] == 'url':
                # Pattern: __init__(self, url, session, token, ...)
                print("[*] Using pattern: JWTScanner(url, session, token)")
                scanner = JWTScanner(self.target, session, jwt_token)

                # Set additional attributes if they exist
                if hasattr(scanner, 'protected_endpoint'):
                    scanner.protected_endpoint = self.protected_endpoint
                if hasattr(scanner, 'wordlist'):
                    scanner.wordlist = self.wordlist
                if hasattr(scanner, 'output'):
                    scanner.output = self.output
                if hasattr(scanner, 'verbose'):
                    scanner.verbose = self.verbose
                if hasattr(scanner, 'timeout'):
                    scanner.timeout = self.timeout
                if hasattr(scanner, 'max_secret_tests'):
                    scanner.max_secret_tests = self.max_secret_tests
                if hasattr(scanner, 'jku_callback_server'):
                    scanner.jku_callback_server = self.jku_callback_server
                if hasattr(scanner, 'public_key_file'):
                    scanner.public_key_file = self.public_key_file
                if hasattr(scanner, 'admin_endpoint'):
                    scanner.admin_endpoint = self.admin_endpoint
                if hasattr(scanner, 'target_user'):
                    scanner.target_user = self.target_user
                if hasattr(scanner, 'token_location'):
                    scanner.token_location = self.token_location

            elif 'config' in params:
                # Pattern: __init__(self, config, session, token)
                print("[*] Using pattern: JWTScanner(config, session, token)")
                scanner = JWTScanner(scanner_args, session, jwt_token)
            else:
                # Pattern: __init__(self, args, session, token) where args is a namespace
                print("[*] Using pattern: JWTScanner(args, session, token)")
                scanner = JWTScanner(scanner_args, session, jwt_token)

            # Run all vulnerability tests
            if hasattr(scanner, 'run'):
                print("[*] Running JWT Scanner...")
                scanner.run()
                print("\n[+] JWT Scanner completed successfully!")
            else:
                print("[WARN] JWTScanner object has no 'run' method")
                print(f"[*] Scanner object type: {type(scanner)}")
                print(f"[*] Available methods: {[m for m in dir(scanner) if not m.startswith('_')]}")

                # Try to find and call the main method if it exists
                if hasattr(scanner, 'scan'):
                    scanner.scan()
                    print("\n[+] JWT Scanner completed successfully!")
                elif hasattr(scanner, 'execute'):
                    scanner.execute()
                    print("\n[+] JWT Scanner completed successfully!")
                elif hasattr(scanner, 'start'):
                    scanner.start()
                    print("\n[+] JWT Scanner completed successfully!")

        except ImportError as e:
            print(f"[ERROR] Could not import JWT Scanner: {e}")
            print("[*] Make sure the JWT scanner is available at src/jwt_scanner/scanner.py")
        except Exception as e:
            print(f"[ERROR] Failed to run JWT Scanner: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()


if __name__ == "__main__":
    # Direct execution using fire instead of argparse
    import fire
    fire.Fire(AuthHandler)
