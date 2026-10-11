import flask
import pickle
import json
def vulnerable():
    data = flask.request.get_data()
    # ruleid: ai-security.python.pickle-untrusted
    return pickle.loads(data)

def safe():
    data = flask.request.get_data()
# ok: ai-security.python.pickle-untrusted
    return json.loads(data)
