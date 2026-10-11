import flask
import requests
def vulnerable():
    url = flask.request.args.get('url')
    return requests.get(url, timeout=5)
