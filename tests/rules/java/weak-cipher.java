import javax.servlet.http.*;
import javax.crypto.Cipher;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ruleid: ai-security.java.weak-cipher
Cipher.getInstance("AES/ECB/PKCS5Padding");
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ok: ai-security.java.weak-cipher
Cipher.getInstance("AES/GCM/NoPadding");
}

}
