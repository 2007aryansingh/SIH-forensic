import os

os.environ.setdefault('API_KEY', 'test-secret')

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

for path in ['/', '/health', '/dashboard', '/docs', '/openapi.json']:
    resp = client.get(path)
    print(f'{path}: {resp.status_code}')

print('docs_url:', app.docs_url)
print('redoc_url:', app.redoc_url)
print('openapi_url:', app.openapi_url)

# check authenticated access works for a protected endpoint
resp = client.get('/health', headers={'x-api-key': 'test-secret'})
print('auth_health_status:', resp.status_code)
