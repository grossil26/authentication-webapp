from mitmproxy import http

class ImplicitFlowChecker:
    """
    A mitmproxy addon to detect and intercept OAuth 2.0 Implicit Flow usage.

    This script monitors authorization requests for the 'response_type=token' parameter,
    which indicates the deprecated Implicit Flow. It also checks redirects to capture
    access tokens exposed in the URL fragment.

    Note: The Implicit Flow is considered insecure as it leaks access tokens in
    browser history and referrer headers.
    """

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Intersects the HTTP request phase to identify Implicit Flow attempts.

        Checks if the authorization request is requesting an access token directly
        rather than an authorization code.

        Args:
            flow (http.HTTPFlow): The current mitmproxy HTTP flow object containing
                                  request data.
        """
        if ("client_id" in flow.request.query
            and flow.request.query.get("response_type") == "token"
        ):
            print(f"\n{'=' * 20}")
            print("Deprecation Warning: Token grant (Implicit Flow) detected!")
            print(f"{'=' * 20}\n")

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Intersects the HTTP response phase to capture leaked tokens.

        Monitors redirection responses (3xx) to see if the Authorization Server
        is appending an access token to the URI fragment.

        Args:
            flow (http.HTTPFlow): The current mitmproxy HTTP flow object containing
                                  response headers.
        """
        if flow.response and flow.response.status_code in (301, 302, 303, 307, 308):
            location = flow.response.headers.get("Location", "")

            # Implicit flow tokens are usually passed in the URI fragment (#)
            if "token" in location:
                print(f"\n{'=' * 20}")
                print("Access Token Intercepted!")
                print(f"Full Redirect URL: {location}")
                print(f"{'=' * 20}\n")


# Register the addon for mitmproxy
addons = [
    ImplicitFlowChecker()
]