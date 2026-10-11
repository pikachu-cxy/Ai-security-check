import yaml
def vulnerable(data):
    return yaml.load(data, Loader=yaml.UnsafeLoader)
