import javax.servlet.http.*;
import java.security.MessageDigest;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ruleid: ai-security.java.weak-digest
MessageDigest.getInstance("MD5");
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ok: ai-security.java.weak-digest
MessageDigest.getInstance("SHA-256");
}

}
