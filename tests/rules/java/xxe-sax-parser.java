import javax.servlet.http.*;
import javax.xml.parsers.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
SAXParserFactory factory=SAXParserFactory.newInstance();
SAXParser parser=factory.newSAXParser();
// ruleid: ai-security.java.xxe-sax-parser
parser.parse(request.getInputStream(),new org.xml.sax.helpers.DefaultHandler());
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
SAXParserFactory factory=SAXParserFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
SAXParser parser=factory.newSAXParser();
// ok: ai-security.java.xxe-sax-parser
parser.parse(request.getInputStream(),new org.xml.sax.helpers.DefaultHandler());
}

}
