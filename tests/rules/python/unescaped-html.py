import flask
from markupsafe import Markup, escape
def vulnerable():
    text = flask.request.args.get('text')
    # ruleid: ai-security.python.unescaped-html
    return Markup(text)

def safe():
    text = flask.request.args.get('text')
    # ok: ai-security.python.unescaped-html
    return escape(text)
