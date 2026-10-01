import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.RestTemplate;
import javax.servlet.http.HttpServletResponse;

class Controller {
    void vulnerable(@RequestParam String command, @RequestParam String name,
                    @RequestParam String url, @RequestParam String next,
                    JdbcTemplate jdbc, RestTemplate rest, HttpServletResponse response) throws Exception {
        // expected: ai-security.java.runtime-exec
        Runtime.getRuntime().exec(command);
        // expected: ai-security.java.spring-jdbc
        jdbc.queryForList("SELECT * FROM users WHERE name='"+name+"'");
        // expected: ai-security.java.spring-resttemplate
        rest.getForObject(url, String.class);
        // expected: ai-security.java.open-redirect
        response.sendRedirect(next);
    }
    void safe(@RequestParam String name, JdbcTemplate jdbc, RestTemplate rest,
              HttpServletResponse response) throws Exception {
        Runtime.getRuntime().exec("/usr/bin/id");
        jdbc.queryForList("SELECT * FROM users WHERE name=?", name);
        rest.getForObject("https://service.example.invalid/health", String.class);
        response.sendRedirect("/home");
    }
}
