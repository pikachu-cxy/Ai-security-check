import flask
def vulnerable(cursor):
    value = flask.request.args.get('id')
    cursor.execute('SELECT name FROM users WHERE id=' + value)
