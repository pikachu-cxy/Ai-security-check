import flask
def vulnerable():
    path = flask.request.args.get('path')
    # ruleid: ai-security.python.path-traversal
    return open(path, 'rb')

def safe():
    # ok: ai-security.python.path-traversal
    return open('static/help.txt', 'rb')
