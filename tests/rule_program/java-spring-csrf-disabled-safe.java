import org.springframework.security.config.annotation.web.builders.HttpSecurity;
class Safe {
  void configure(HttpSecurity http) throws Exception {
    http.csrf();
  }
}
