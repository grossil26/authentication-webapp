import requests
from bs4 import BeautifulSoup
import sys

print("Connecting to DVWA Setup Page...")
session = requests.Session()
setup_url = 'http://127.0.0.1/setup.php'

# 1. Get the setup page
try:
    response = session.get(setup_url, timeout=10)
    response.raise_for_status()
except requests.exceptions.RequestException as e:
    print(f"FATAL: Could not reach the setup URL ({setup_url}).")
    print("Make sure your Docker container is actually running!")
    print(f"Error details: {e}")
    sys.exit(1)  # This stops the script cleanly

soup = BeautifulSoup(response.text, 'html.parser')

# 2. Extract the setup token
token_tag = soup.find('input', {'name': 'user_token'})
if token_tag:
    token = token_tag['value']
    print(f"Found Setup Token: {token}")

    # 3. Submit the setup form to initialize DVWA's internal MySQL database.
    session.post('http://127.0.0.1/setup.php', data={
        'create_db': 'Create / Reset Database',
        'user_token': token
    })
    print("Target Database Initialized Successfully.")
else:
    print("Could not find token. Is the container running?")