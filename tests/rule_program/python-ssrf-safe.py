import flask
import requests
def safe():
    return requests.get('https://example.invalid/status', timeout=5)
