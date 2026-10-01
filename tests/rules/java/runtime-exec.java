import javax.servlet.http.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
String command=request.getParameter("command");
// ruleid: ai-security.java.runtime-exec
Runtime.getRuntime().exec(command);
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ok: ai-security.java.runtime-exec
Runtime.getRuntime().exec("/usr/bin/id");
String chosen=request.getParameter("command");
if ("status".equals(chosen)) {
// ok: ai-security.java.runtime-exec
Runtime.getRuntime().exec("/usr/bin/id");
}
}

}
