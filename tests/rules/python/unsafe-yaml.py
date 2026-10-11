import yaml
def vulnerable(data):
    # ruleid: ai-security.python.unsafe-yaml
    return yaml.load(data, Loader=yaml.UnsafeLoader)

def safe(data):
    # ok: ai-security.python.unsafe-yaml
    return yaml.safe_load(data)
