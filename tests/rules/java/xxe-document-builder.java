import javax.servlet.http.*;
import javax.xml.parsers.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();
DocumentBuilder parser=factory.newDocumentBuilder();
// ruleid: ai-security.java.xxe-document-builder
parser.parse(request.getInputStream());
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
DocumentBuilder parser=factory.newDocumentBuilder();
// ok: ai-security.java.xxe-document-builder
parser.parse(request.getInputStream());
}

}
