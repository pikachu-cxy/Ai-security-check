import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
class Safe {
  void show(HttpServletRequest request, HttpServletResponse response) throws Exception {
    response.getWriter().print("Hello");
  }
}
