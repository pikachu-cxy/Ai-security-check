import requests
def vulnerable():
    return requests.get('https://example.invalid', verify=False)
