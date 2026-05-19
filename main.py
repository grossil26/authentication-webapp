import fire

from src.jwt_scanner.scanner import JWTScanner
from src.stateful_authentication.stateful_auth import StatefulAuthentication
from src.oauth.oauth import OAuthToolkit

class Tools:
    """
    Security  testing toolkit.

    Available tools:
        jwt_scanner             - Test a target for 8 critical JWT vulnerabilities.
        stateful_authentication - Obtain an authenticated session via form, basic, or JSON auth.
        oauth_toolkit           - Test Targets That Rely on OAuth requests.
    """

    def __init__(self):
        self.jwt_scanner = JWTScanner
        self.stateful_authentication = StatefulAuthentication
        self.oauth_toolkit = OAuthToolkit

if __name__ == "__main__":
    fire.Fire(Tools)