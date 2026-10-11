import flask
import requests
def vulnerable():
    url = flask.request.args.get('url')
    # ruleid: ai-security.python.ssrf
    return requests.get(url, timeout=5)

def safe():
    # ok: ai-security.python.ssrf
    return requests.get('https://example.invalid/status', timeout=5)
