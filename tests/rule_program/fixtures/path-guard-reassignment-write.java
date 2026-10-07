import javax.servlet.http.HttpServletRequest;
import java.nio.file.*;
class GuardReassignment { void test(HttpServletRequest request) throws Exception {
 Path base = Paths.get("/srv/files").toAbsolutePath().normalize();
 Path p = base.resolve(request.getParameter("name")).normalize();
 if (!p.startsWith(base)) { throw new SecurityException(); }
 p = Paths.get(request.getParameter("replacement"));
 Files.write(p, new byte[] {1});
} }
