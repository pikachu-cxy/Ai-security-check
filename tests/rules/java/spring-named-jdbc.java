// Synthetic API examples; no application data or executable database setup.
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.web.bind.annotation.RequestParam;
import java.util.Map;

class NamedJdbcFixture {
    void query(javax.servlet.http.HttpServletRequest request, NamedParameterJdbcTemplate jdbc) {
        String sql = "SELECT id FROM accounts WHERE name='" + request.getParameter("name") + "'";
        // ruleid: ai-security.java.spring-named-jdbc
        jdbc.queryForList(sql, Map.of());
    }

    void update(jakarta.servlet.http.HttpServletRequest request, NamedParameterJdbcOperations jdbc) {
        String sql = "UPDATE accounts SET label='" + request.getHeader("label") + "'";
        // ruleid: ai-security.java.spring-named-jdbc
        jdbc.update(sql, new MapSqlParameterSource());
    }

    void annotated(@RequestParam("sort") String sort, NamedParameterJdbcTemplate jdbc) {
        // ruleid: ai-security.java.spring-named-jdbc
        jdbc.queryForMap("SELECT id FROM accounts ORDER BY " + sort, Map.of());
    }

    void dynamicTemplateStillUnsafe(javax.servlet.http.HttpServletRequest request, NamedParameterJdbcTemplate jdbc) {
        String sql = "SELECT id FROM " + request.getParameter("table") + " WHERE name=:name";
        // ruleid: ai-security.java.spring-named-jdbc
        jdbc.queryForList(sql, Map.of("name", "synthetic"));
    }

    void boundValue(javax.servlet.http.HttpServletRequest request, NamedParameterJdbcTemplate jdbc) {
        // ok: ai-security.java.spring-named-jdbc
        jdbc.queryForList("SELECT id FROM accounts WHERE name=:name", Map.of("name", request.getParameter("name")));
    }

    void boundUpdate(jakarta.servlet.http.HttpServletRequest request, NamedParameterJdbcOperations jdbc) {
        // ok: ai-security.java.spring-named-jdbc
        jdbc.update("UPDATE accounts SET label=:label", new MapSqlParameterSource("label", request.getParameter("label")));
    }

    void fixedTemplate(javax.servlet.http.HttpServletRequest request, NamedParameterJdbcTemplate jdbc) {
        String ignored = request.getParameter("table");
        // ok: ai-security.java.spring-named-jdbc
        jdbc.queryForList("SELECT id FROM accounts", Map.of());
    }

    void exactSelection(javax.servlet.http.HttpServletRequest request, NamedParameterJdbcTemplate jdbc) {
        String requested = request.getParameter("sort");
        String sql = "SELECT id FROM accounts ORDER BY id";
        if ("name".equals(requested)) sql = "SELECT id FROM accounts ORDER BY name";
        // ok: ai-security.java.spring-named-jdbc
        jdbc.queryForList(sql, Map.of());
    }
}
