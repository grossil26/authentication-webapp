# Automated Security Scanning for Modern Web Authentication Flows
### MICAC SoA 2026: C&D

A comprehensive security testing framework for web applications, supporting authentication handling, JWT vulnerability scanning, and OAuth 2.0 security testing. Designed to automate the detection of common flaws in modern authentication mechanisms.
# Features
* **Stateful Authentication** – Supports Form, Basic, JSON, and Bearer token login strategies.
* **JWT Security Scanner** – Tests 8 critical JWT vulnerabilities (alg:none, missing signature, weak secrets, jwk/jku injection, KID path traversal, algorithm confusion, SQL injection via KID).
* **OAuth 2.0 Toolkit** – Mitmproxy-based addons to test Implicit Flow, Redirect URI, and CSRF (state parameter) vulnerabilities.
* **Token Lifecycle Management** – Automatic JWT refresh and expiry monitoring.
* **Modular Design** – Authentication and scanning are decoupled for flexible usage.

### **Installation**
### Using UV (Recommended)
~[UV](https://github.com/astral-sh/uv)~ is a fast Python package installer and resolver.

```bash
git clone https://git.mif.vu.lt/mapl2005/authentication-webapp-project
cd authentication-webapp-project

# Create a virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e .
```

Alternatively, install directly with UV:

`uv pip install -r pyproject.toml`

> **Note**: For cryptography (required for jwk/jku tests) you may need system build tools:
> * Ubuntu/Debian: sudo apt install build-essential libssl-dev libffi-dev python3-dev
> * macOS: xcode-select --install

### **Using pip (Classic)**
`pip install -e .`

# **Usage**
The toolkit is exposed via a command-line interface built with ~[Fire](https://github.com/google/python-fire)~.
`uv run main.py <tool> [arguments]`

### 1\. Authentication Only (`auth`)
Performs login using the specified method and returns an authenticated session and any extracted JWT token.

```bash
uv run main.py auth \
  --login_url=https://example.com/login \
  --username=admin \
  --password=P@ssw0rd \
  --auth_type=form \
  --success_string="Dashboard" \
  --verbose
```

**Arguments** (required for non-bearer types):
| **Argument** | **Description** | **Default** |
|:-:|:-:|:-:|
| --login_url | Target login URL | None |
| --username | Username for login | None |
| --password | Password for login | None |
| --auth_type | One of: form, basic, json, bearer | None |
| --user_field | Username field name (form/json) | username |
| --pass_field | Password field name (form/json) | password |
| --csrf_field | CSRF token field name (form only) | csrf |
| --success_string | Text indicating successful login | None |
| --token_fields | Comma-separated JSON fields for JWT extraction | token,access_token,jwt,id_token |
| --token | Pre‑existing bearer token (bearer auth) | None |
| --verbose | Enable verbose output | False |

**2\. JWT Scanner (`jwt_scanner`)**
Authenticates, extracts the JWT (if any), then runs all 8 vulnerability tests against a protected endpoint.

```bash
uv run main.py jwt_scanner \
  --login_url=https://example.com/login \
  --username=admin \
  --password=P@ssw0rd \
  --auth_type=json \
  --target=https://example.com \
  --protected_endpoint=/api/admin \
  --wordlist=secrets.txt \
  --output=report.json \
  --verbose
```

**Additional arguments** (beyond those in auth):
| **Argument** | **Description** | **Default** |
|:-:|:-:|:-:|
| --target | Base URL of the target application (required) | None |
| --protected_endpoint | Endpoint that requires a valid JWT (required) | None |
| --wordlist | Path to weak secrets dictionary (for brute‑force) | "" |
| --output | Output report file (JSON) | jwt_scan_report.json |
| --timeout | Request timeout in seconds | 10 |
| --max_secret_tests | Maximum number of secrets to test (0 = all) | 0 |
| --jku_callback_server | URL of a server hosting malicious JWKS (for jku injection) | "" |
| --public_key_file | PEM file or Base64‑encoded public key (algorithm confusion test) | None |
| --admin_endpoint | Protected endpoint for algorithm confusion (e.g. /admin) | /admin |
| --target_user | User to impersonate in forged tokens | administrator |
| --token_location | Where to send token: header, cookie, param, both | both |
> **Note**: The algorithm confusion test (test_7_algorithm_confusion) requires a valid public key file to be supplied via --public_key_file. If not provided, this test is skipped.

### 3\. OAuth Toolkit (oauth_toolkit)
Launches mitmproxy with one of three addons to test OAuth 2.0 security flaws.

`uv run main.py oauth_toolkit --tool=[TOOL OPTION HERE]`

Available subcommands (each runs a mitmproxy addon):

| **Subcommand** | **Addon File** | **Description** |
|:-:|:-:|:-:|
| implicit | implicit_flow.py | Detects deprecated Implicit Flow (response_type=token) and captures tokens in URL fragments. |
| redirect | redirect_uri.py | Tests for Open Redirect / OAuth callback injection by replacing redirect_uri. |
| state | state_check.py | Checks for missing or mismatched state parameter (CSRF protection). |

**Example** (start mitmproxy on default port 8080, then configure browser to proxy through it):

` uv run main.py oauth_toolkit --tool=redirect`

After starting, mitmproxy will intercept and modify OAuth requests. The script runs until interrupted (Ctrl+C).

> **Prerequisite**: ~[mitmproxy](https://mitmproxy.org/)~ must be installed (included in dependencies) and the system proxy must be configured to use localhost:8080. For HTTPS interception, install the mitmproxy certificate.
# Docker
You can run the toolkit inside a Docker container to avoid dependency conflicts and simplify mitmproxy usage.

```bash
# Build image
docker build -t auth-toolkit .

# Run authentication only (example)
docker run --rm auth-toolkit \
  --login_url=https://example.com/login \
  --username=admin \
  --password=pass \
  --auth_type=form

# Run OAuth redirect test (mitmproxy needs network access)
docker run --rm -p 8080:8080 auth-toolkit python -m oauth_toolkit redirect
```

For mitmproxy to intercept traffic from other containers or the host, use --network=host (Linux) or appropriate port forwarding.

**Project Structure**
```bash
.
├── src/
│   ├── authentication/
│   │   ├── AuthHandler.py      # Main authentication logic
│   │   └── token_manager.py    # Token refresh & expiry
│   ├── jwt_scanner/
│   │   └── scanner.py          # 8 JWT vulnerability tests
│   ├── oauth/
│   │   ├── oauth.py            # OAuth subcommand dispatcher
│   │   ├── implicit_flow.py    # Implicit Flow detection addon
│   │   ├── redirect_uri.py     # Redirect URI injection addon
│   │   └── state_check.py      # CSRF (state) check addon
│   └── main.py                 # Fire CLI entry point
├── pyproject.toml
└── README.md
```