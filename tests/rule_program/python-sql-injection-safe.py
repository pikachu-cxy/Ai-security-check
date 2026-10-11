import flask
def safe(cursor):
    value = flask.request.args.get('id')
    cursor.execute('SELECT name FROM users WHERE id=%s', (value,))
