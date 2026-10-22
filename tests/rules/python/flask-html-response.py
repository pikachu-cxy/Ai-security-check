"""Static Flask response contracts; never run this fixture as an application."""
import flask
import html
from markupsafe import escape


@app.route('/greeting')
def greeting():
    name = flask.request.args.get('name')
    # ruleid: ai-security.python.flask-html-response
    return f'Hello {name}'


@app.route('/accumulated', methods=['POST'])
def accumulated():
    name = flask.request.form.get('name')
    response = ''
    # ruleid: ai-security.python.flask-html-response
    response += f'<p>{name}</p>'
    return response


@app.route('/assigned')
def assigned():
    name = flask.request.headers.get('x-name')
    # ruleid: ai-security.python.flask-html-response
    response = '<p>' + name + '</p>'
    return response


@app.route('/formatted')
def formatted():
    name = flask.request.form.getlist('name')[0]
    # ruleid: ai-security.python.flask-html-response
    return '<p>{}</p>'.format(name)


@app.route('/percent')
def percent():
    name = flask.request.cookies.get('name')
    # ruleid: ai-security.python.flask-html-response
    return '<p>%s</p>' % name


@app.route('/escaped')
def escaped():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    return f'<p>{html.escape(name)}</p>'


@app.route('/markup-escaped')
def markup_escaped():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    return '<p>{}</p>'.format(escape(name))


@app.route('/json')
def json_body():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    return {'name': f'{name}'}


@app.route('/jsonify')
def json_result():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    return flask.jsonify({'name': name})


@app.route('/text')
def text_result():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    return f'Hello {name}', 200, {'Content-Type': 'text/plain'}


@app.route('/response-text')
def explicit_text():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    return flask.Response(f'{name}', mimetype='text/plain')


@app.route('/template')
def autoescaped_template():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    return flask.render_template('hello.html', name=name)


@app.route('/helper')
def helper_result():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    return f'{unknown_helper(name)}'


@app.route('/numeric')
def numeric_result():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    return f'{int(name)}'


def ordinary_function():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    return f'Hello {name}'


@app.route('/discarded')
def discarded():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    response = f'Hello {name}'
    response = 'fixed'
    return response


@app.route('/explicit-content-type')
def content_type_after_construction():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    response = f'Hello {name}'
    return response, 200, {'Content-Type': 'text/plain'}


@app.route('/assigned-json')
def assigned_json():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    response = {'name': f'{name}'}
    return response


@app.route('/assigned-tuple')
def assigned_tuple():
    name = flask.request.args.get('name')
    # ok: ai-security.python.flask-html-response
    response = f'{name}', 200, {'Content-Type': 'text/plain'}
    return response


@app.route('/accumulated-list')
def accumulated_list():
    name = flask.request.args.get('name')
    response = []
    # ok: ai-security.python.flask-html-response
    response += f'{name}'
    return response


@app.route('/split')
def split_string():
    value = flask.request.form.get('name')
    first = value.split(' ')[0]
    # ruleid: ai-security.python.flask-html-response
    return f'<p>{first}</p>'


@app.route('/base64')
def reversible_encoding():
    import base64
    value = flask.request.form.getlist('name')[0]
    encoded = base64.b64encode(value.encode('utf-8'))
    decoded = base64.b64decode(encoded).decode('utf-8')
    # ruleid: ai-security.python.flask-html-response
    return '<p>{}</p>'.format(decoded)


@app.route('/base64-escaped')
def reversible_encoding_then_escape():
    import base64
    value = flask.request.form.getlist('name')[0]
    encoded = base64.b64encode(value.encode('utf-8'))
    decoded = base64.b64decode(encoded).decode('utf-8')
    # ok: ai-security.python.flask-html-response
    return '<p>{}</p>'.format(html.escape(decoded))


@app.route('/unused-format-argument')
def unused_format_argument():
    value = flask.request.form.get('name')
    # ok: ai-security.python.flask-html-response
    return 'fixed'.format(value)


@app.route('/different-format-argument')
def different_format_argument():
    value = flask.request.form.get('name')
    # ok: ai-security.python.flask-html-response
    return '{1}'.format(value, 'fixed')


@app.route('/escaped-format-braces')
def escaped_format_braces():
    value = flask.request.form.get('name')
    # ok: ai-security.python.flask-html-response
    return '{{}}'.format(value)


@app.route('/no-percent-placeholder')
def no_percent_placeholder():
    value = flask.request.form.get('name')
    # ok: ai-security.python.flask-html-response
    return 'fixed' % value
