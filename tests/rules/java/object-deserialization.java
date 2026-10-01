import javax.servlet.http.*;
import java.io.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
ObjectInputStream stream=new ObjectInputStream(request.getInputStream());
// ruleid: ai-security.java.object-deserialization
stream.readObject();
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
ObjectInputStream stream=new ObjectInputStream(new FileInputStream("/srv/trusted/internal.bin"));
// ok: ai-security.java.object-deserialization
stream.readObject();
}

}
