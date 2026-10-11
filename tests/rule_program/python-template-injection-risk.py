import flask
def vulnerable():
    template = flask.request.args.get('template')
    return flask.render_template_string(template)
