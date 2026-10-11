import flask
from markupsafe import Markup, escape
def safe():
    text = flask.request.args.get('text')
    return escape(text)
