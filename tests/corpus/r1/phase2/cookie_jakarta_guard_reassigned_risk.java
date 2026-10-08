import jakarta.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
String value=""; Cookie[] cookies=request.getCookies();if(cookies!=null) { for(Cookie cookie:cookies) {value=cookie.getValue();break;} }
Path base=Paths.get("/srv/data").toAbsolutePath().normalize();Path p=base.resolve(value).normalize();if(!p.startsWith(base)) {throw new IllegalArgumentException();}
p=Paths.get(value);Files.readAllBytes(p);
 }

}
