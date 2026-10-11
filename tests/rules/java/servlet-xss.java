import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
class Vulnerable {
  void show(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String text = request.getParameter("text");
    // ruleid: ai-security.java.servlet-xss
    response.getWriter().print(text);
  }
}

class Safe {
  void show(HttpServletRequest request, HttpServletResponse response) throws Exception {
    // ok: ai-security.java.servlet-xss
    response.getWriter().print("Hello");
  }
}
