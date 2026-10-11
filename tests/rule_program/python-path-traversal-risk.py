import flask
def vulnerable():
    path = flask.request.args.get('path')
    return open(path, 'rb')
