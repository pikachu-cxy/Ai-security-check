import flask
def vulnerable():
    template = flask.request.args.get('template')
    # ruleid: ai-security.python.template-injection
    return flask.render_template_string(template)

def safe():
    name = flask.request.args.get('name')
    # ok: ai-security.python.template-injection
    return flask.render_template_string('Hello {{ name }}', name=name)
