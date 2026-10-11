import flask
def safe():
    return open('static/help.txt', 'rb')
