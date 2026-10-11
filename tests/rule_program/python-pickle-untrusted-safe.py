import flask
import pickle
import json
def safe():
    data = flask.request.get_data()
    return json.loads(data)
