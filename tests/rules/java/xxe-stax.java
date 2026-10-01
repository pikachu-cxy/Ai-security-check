import javax.servlet.http.*;
import javax.xml.stream.XMLInputFactory;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
XMLInputFactory factory=XMLInputFactory.newFactory();
// ruleid: ai-security.java.xxe-stax
factory.createXMLStreamReader(request.getInputStream());
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
XMLInputFactory factory=XMLInputFactory.newFactory();
factory.setProperty(XMLInputFactory.SUPPORT_DTD,false);
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES,false);
// ok: ai-security.java.xxe-stax
factory.createXMLStreamReader(request.getInputStream());
}

}
