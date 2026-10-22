import flask
import configparser
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


def dictionary_query(cursor):
    values={}
    values['fixed']='public'
    values['input']=flask.request.headers.get('X-Account')
    values['other']='another constant'
    account=values['input']
    # ruleid: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner='+account)


def dictionary_bound_value(cursor):
    values={}
    values['input']=flask.request.cookies.get('account')
    values['other']='another constant'
    # ok: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner=?', (values['input'],))


def config_query(cursor):
    config = configparser.ConfigParser()
    config.add_section('query')
    config.set('query', 'owner', flask.request.form.get('account'))
    account = config.get('query', 'owner')
    # ruleid: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner=' + account)


def config_local_import_query(cursor):
    import configparser as cp
    config = cp.ConfigParser()
    config.add_section('query')
    config.set('query', 'owner', flask.request.headers.get('X-Account'))
    account = config.get('query', 'owner')
    # Changing the container afterwards does not sanitize the copied string.
    config.set('query', 'owner', 'fixed')
    # ruleid: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner=' + account)


def config_safe_key(cursor):
    config = configparser.ConfigParser()
    config.add_section('query')
    config.set('query', 'fixed', 'public')
    config.set('query', 'owner', flask.request.form.get('account'))
    account = config.get('query', 'fixed')
    # ok: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner=' + account)


def config_safe_section(cursor):
    config = configparser.ConfigParser()
    config.add_section('query')
    config.add_section('other')
    config.set('other', 'owner', 'public')
    config.set('query', 'owner', flask.request.form.get('account'))
    account = config.get('other', 'owner')
    # ok: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner=' + account)


def config_overwrite_safe(cursor):
    config = configparser.ConfigParser()
    config.add_section('query')
    config.set('query', 'owner', flask.request.form.get('account'))
    config.set('query', 'owner', 'public')
    account = config.get('query', 'owner')
    # ok: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner=' + account)


def config_bound_value(cursor):
    config = configparser.ConfigParser()
    config.add_section('query')
    config.set('query', 'owner', flask.request.form.get('account'))
    account = config.get('query', 'owner')
    # ok: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner=?', (account,))


def unrelated_set_get(cursor, store):
    store.set('query', 'owner', flask.request.form.get('account'))
    account = store.get('query', 'owner')
    # ok: ai-security.python.sql-injection
    cursor.execute('SELECT balance FROM accounts WHERE owner=' + account)
