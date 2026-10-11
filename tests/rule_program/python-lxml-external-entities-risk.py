from lxml import etree
def vulnerable():
    return etree.XMLParser(resolve_entities=True)
