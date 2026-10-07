import javax.servlet.http.*;
import java.io.*;
import java.nio.file.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
String path=request.getParameter("path");
// ruleid: ai-security.java.file-access, ai-security.java.arbitrary-file-read
new FileInputStream(path);
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ok: ai-security.java.file-access
new FileInputStream("/srv/config/service.txt");
// ok: ai-security.java.file-access
Files.readString(Paths.get("/srv/config/service.txt"));
}

}
