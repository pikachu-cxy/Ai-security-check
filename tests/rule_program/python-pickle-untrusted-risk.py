import flask
import pickle
import json
def vulnerable():
    data = flask.request.get_data()
    return pickle.loads(data)
