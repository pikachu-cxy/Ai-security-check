import org.springframework.security.config.annotation.web.builders.HttpSecurity;
class Vulnerable {
  void configure(HttpSecurity http) throws Exception {
    // ruleid: ai-security.java.spring-csrf-disabled
    http.csrf().disable();
  }
}

class Safe {
  void configure(HttpSecurity http) throws Exception {
    // ok: ai-security.java.spring-csrf-disabled
    http.csrf();
  }
}
