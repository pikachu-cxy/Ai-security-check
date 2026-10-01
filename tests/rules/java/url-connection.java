import javax.servlet.http.*;
import java.net.URL;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
URL url=new URL(request.getParameter("url"));
// ruleid: ai-security.java.url-connection
url.openConnection();
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
URL url=new URL("https://service.example.invalid/health");
// ok: ai-security.java.url-connection
url.openConnection();
}

}
