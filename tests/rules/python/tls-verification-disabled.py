import requests
def vulnerable():
    # ruleid: ai-security.python.tls-verification-disabled
    return requests.get('https://example.invalid', verify=False)

def safe():
    # ok: ai-security.python.tls-verification-disabled
    return requests.get('https://example.invalid', verify=True)
