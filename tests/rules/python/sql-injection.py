import flask
def vulnerable(cursor):
    value = flask.request.args.get('id')
    # ruleid: ai-security.python.sql-injection
    cursor.execute('SELECT name FROM users WHERE id=' + value)

def safe(cursor):
    value = flask.request.args.get('id')
    # ok: ai-security.python.sql-injection
    cursor.execute('SELECT name FROM users WHERE id=%s', (value,))


def header_query(cursor):
    account = flask.request.headers.get('X-Account')
    # ruleid: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner=' + account)


def cookie_query(cursor):
    account = flask.request.cookies['account']
    # ruleid: ai-security.python.sql-injection
    cursor.execute(f'SELECT balance FROM accounts WHERE owner={account}')


def header_bound_value(cursor):
    account = flask.request.headers['X-Account']
    # ok: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner=?', (account,))


def cookie_bound_value(cursor):
    account = flask.request.cookies.get('account')
    # ok: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner=%s', (account,))
