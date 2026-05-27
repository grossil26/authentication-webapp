
import fire

from src.authentication.AuthHandler import AuthHandler
from src.oauth.oauth import OAuthToolkit

class Tools:
    """
    Security testing toolkit.

    Available tools:
        auth           - Authentication only (get session and JWT token)
        jwt_scanner    - Full workflow: Authentication + JWT vulnerability scanning
        oauth_toolkit  - Test Targets That Rely on OAuth requests
    """

    def auth(self, **kwargs):
        """
        Authentication only mode.
        Returns authenticated session and JWT token without scanning.

        Required arguments:
            --login_url     Target login URL
            --username      Username to inject
            --password      Password to inject
            --auth_type     Type of login (form, basic, json, bearer)

        Optional arguments:
            --user_field    HTML name for username field (default: username)
            --pass_field    HTML name for password field (default: password)
            --csrf_field    HTML name for CSRF token (default: csrf)
            --success_string Text indicating successful login
            --token_fields  Comma-separated JSON fields for JWT extraction
            --token         Pre-existing bearer token (for bearer auth)
            --verbose       Enable verbose output
        """
        handler = AuthHandler(scan_mode=False, **kwargs)
        return handler()

    def jwt_scanner(self, **kwargs):
        """
        Full workflow: Authentication + JWT scanning.
        Performs authentication and then runs all JWT vulnerability tests.

        Required arguments:
            --login_url          Target login URL
            --username           Username to inject
            --password           Password to inject
            --auth_type          Type of login (form, basic, json, bearer)
            --target             Target base URL for scanning
            --protected_endpoint Protected endpoint requiring JWT

        Optional arguments:
            --user_field         HTML name for username field (default: username)
            --pass_field         HTML name for password field (default: password)
            --csrf_field         HTML name for CSRF token (default: csrf)
            --success_string     Text indicating successful login
            --token_fields       Comma-separated JSON fields for JWT extraction
            --token              Pre-existing bearer token (for bearer auth)
            --wordlist           Path to weak secrets dictionary
            --output             Output report file (default: jwt_scan_report.json)
            --verbose            Enable verbose output
            --timeout            Request timeout (default: 10)
            --max_secret_tests   Max secrets to test (default: 0 = all)
            --jku_callback_server Server URL for jku testing
            --public_key_file    PEM file or Base64 encoded public key
            --admin_endpoint     Protected endpoint for algorithm confusion (default: /admin)
            --target_user        User to impersonate (default: administrator)
            --token_location     Where to send token (header, cookie, param, both)
        """
        handler = AuthHandler(scan_mode=True, **kwargs)
        return handler()

    def oauth_toolkit(self):
        """OAuth testing toolkit."""
        return OAuthToolkit

if __name__ == "__main__":
    fire.Fire(Tools)

