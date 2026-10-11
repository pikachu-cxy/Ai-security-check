import flask
def vulnerable(cursor):
    value = flask.request.args.get('id')
    # ruleid: ai-security.python.sql-injection
    cursor.execute('SELECT name FROM users WHERE id=' + value)

def safe(cursor):
    value = flask.request.args.get('id')
    # ok: ai-security.python.sql-injection
    cursor.execute('SELECT name FROM users WHERE id=%s', (value,))
