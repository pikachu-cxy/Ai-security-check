import flask
from markupsafe import Markup, escape
def vulnerable():
    text = flask.request.args.get('text')
    return Markup(text)
