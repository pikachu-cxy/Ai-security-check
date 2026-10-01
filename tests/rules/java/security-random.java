import javax.servlet.http.*;
import java.util.Random;
import java.security.SecureRandom;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
Random random=new Random();
// ruleid: ai-security.java.security-random
int resetCode=random.nextInt(999999);
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
Random random=new Random();
// ok: ai-security.java.security-random
int dice=random.nextInt(6);
SecureRandom secure=new SecureRandom();
// ok: ai-security.java.security-random
int resetCode=secure.nextInt(999999);
}

}
