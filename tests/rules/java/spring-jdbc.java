import javax.servlet.http.*;
import org.springframework.jdbc.core.JdbcTemplate;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
JdbcTemplate jdbc=new JdbcTemplate();
// ruleid: ai-security.java.spring-jdbc
jdbc.queryForList("SELECT * FROM users WHERE name='"+request.getParameter("name")+"'");
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
JdbcTemplate jdbc=new JdbcTemplate();
// ok: ai-security.java.spring-jdbc
jdbc.queryForList("SELECT * FROM users WHERE name=?",request.getParameter("name"));
}

}
