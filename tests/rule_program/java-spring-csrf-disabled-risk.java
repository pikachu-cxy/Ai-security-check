import org.springframework.security.config.annotation.web.builders.HttpSecurity;
class Vulnerable {
  void configure(HttpSecurity http) throws Exception {
    http.csrf().disable();
  }
}
