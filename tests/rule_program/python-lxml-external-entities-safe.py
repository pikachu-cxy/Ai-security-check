from lxml import etree
def safe():
    return etree.XMLParser(resolve_entities=False, no_network=True)
