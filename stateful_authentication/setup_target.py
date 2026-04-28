import requests
from bs4 import BeautifulSoup

print("Connecting to DVWA Setup Page...")
session = requests.Session()

# 1. Get the setup page
response = session.get('http://127.0.0.1/setup.php')
soup = BeautifulSoup(response.text, 'html.parser')

# 2. Extract the setup token
token_tag = soup.find('input', {'name': 'user_token'})
if token_tag:
    token = token_tag['value']
    print(f"Found Setup Token: {token}")

    # 3. Submit the setup form
    session.post('http://127.0.0.1/setup.php', data={
        'create_db': 'Create / Reset Database',
        'user_token': token
    })
    print("Target Database Initialized Successfully.")
else:
    print("Could not find token.")