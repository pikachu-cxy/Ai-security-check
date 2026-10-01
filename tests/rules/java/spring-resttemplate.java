import javax.servlet.http.*;
import org.springframework.web.client.RestTemplate;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
RestTemplate rest=new RestTemplate();
// ruleid: ai-security.java.spring-resttemplate
rest.getForObject(request.getParameter("url"),String.class);
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
RestTemplate rest=new RestTemplate();
// ok: ai-security.java.spring-resttemplate
rest.getForObject("https://service.example.invalid/health",String.class);
}

}
