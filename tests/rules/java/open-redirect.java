import javax.servlet.http.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ruleid: ai-security.java.open-redirect
response.sendRedirect(request.getParameter("next"));
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ok: ai-security.java.open-redirect
response.sendRedirect("/home");
}

}
