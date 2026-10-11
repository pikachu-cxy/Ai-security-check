from lxml import etree
def vulnerable():
    # ruleid: ai-security.python.lxml-external-entities
    return etree.XMLParser(resolve_entities=True)

def safe():
    # ok: ai-security.python.lxml-external-entities
    return etree.XMLParser(resolve_entities=False, no_network=True)
