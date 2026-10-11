import flask
def safe():
    name = flask.request.args.get('name')
    return flask.render_template_string('Hello {{ name }}', name=name)
