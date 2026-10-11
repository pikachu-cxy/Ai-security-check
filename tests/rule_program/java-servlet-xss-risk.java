import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
class Vulnerable {
  void show(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String text = request.getParameter("text");
    response.getWriter().print(text);
  }
}
