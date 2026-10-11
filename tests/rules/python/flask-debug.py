import flask
app = flask.Flask(__name__)
# ruleid: ai-security.python.flask-debug
app.run(debug=True)

# ok: ai-security.python.flask-debug
app.run(debug=False)
