import javax.servlet.http.*;
import java.beans.XMLDecoder;
import java.io.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
XMLDecoder decoder=new XMLDecoder(request.getInputStream());
// ruleid: ai-security.java.xml-decoder
decoder.readObject();
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
XMLDecoder decoder=new XMLDecoder(new FileInputStream("/srv/trusted/internal.xml"));
// ok: ai-security.java.xml-decoder
decoder.readObject();
}

}
