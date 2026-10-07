import javax.servlet.http.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ruleid: ai-security.java.process-builder
ProcessBuilder builder=new ProcessBuilder(request.getParameter("command"));
builder.start();
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
ProcessBuilder builder=new ProcessBuilder("/usr/bin/id");
// ok: ai-security.java.process-builder
builder.start();
}

}
