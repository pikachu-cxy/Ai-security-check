import requests
def safe():
    return requests.get('https://example.invalid', verify=True)
