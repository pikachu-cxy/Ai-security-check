import javax.servlet.http.*;
import javax.naming.InitialContext;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
InitialContext context=new InitialContext();
// ruleid: ai-security.java.jndi-lookup
context.lookup(request.getParameter("name"));
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
InitialContext context=new InitialContext();
// ok: ai-security.java.jndi-lookup
context.lookup("java:comp/env/jdbc/database");
}

}
