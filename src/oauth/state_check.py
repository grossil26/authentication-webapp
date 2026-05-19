from mitmproxy import http


class StateCheck:
    """
    A mitmproxy addon to detect missing or mismatched CSRF protection (state parameter).

    This script monitors OAuth 2.0 authorization flows to ensure the 'state' parameter
    is implemented. It flags requests missing the parameter and verifies that
    the authorization server returns the identical state value during redirection.

    Note: The 'state' parameter is critical for preventing Cross-Site Request
    Forgery (CSRF) attacks during the OAuth handshake.
    """

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Intersects the HTTP request phase to check for the 'state' parameter.

        Identifies OAuth 2.0 authorization requests by checking for 'response_type'
        and 'client_id'. If the 'state' parameter is missing, it logs a security
        warning indicating potential CSRF vulnerability.

        Args:
            flow (http.HTTPFlow): The current mitmproxy HTTP flow object containing
                                  request data.
        """
        if "response_type" in flow.request.query and "client_id" in flow.request.query:
            if "state" not in flow.request.query:
                print(f"\n{'='*20}")
                print("Security Warning: Missing 'state' parameter!")
                print(f"Target: {flow.request.host}")
                print(f"{'='*20}\n")

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Intersects the HTTP response phase to ensure state integrity.

        Monitors redirection responses (3xx) to verify that if a 'state' was
        provided in the initial request, the exact same value is returned
        in the redirect URL.

        Args:
            flow (http.HTTPFlow): The current mitmproxy HTTP flow object containing
                                  response headers and original request data.
        """
        # Check if the response is a redirect
        if flow.response and flow.response.status_code in (301, 302, 303, 307, 308):
            location = flow.response.headers.get("Location", "")

            # If the request had a state, the response (redirect) MUST have the same state
            if "state" in flow.request.query:
                expected_state = flow.request.query["state"]

                if "state=" not in location:
                    print(f"\n{'='*20}")
                    print("CSRF Risk: 'state' sent in request but missing in redirect!")
                    print(f"Location: {location}")
                    print(f"{'='*20}\n")

                elif expected_state not in location:
                    print(f"\n{'='*20}")
                    print("Critical: 'state' mismatch detected!")
                    print(f"Expected: {expected_state}")
                    print(f"Received in Redirect: {location}")
                    print(f"{'='*20}\n")


# Register the addon for mitmproxy
addons = [
    StateCheck()
]