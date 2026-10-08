import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
String value=""; Cookie[] cookies=request.getCookies();if(cookies!=null) { for(Cookie cookie:cookies) {value=cookie.getValue();break;} }
PreparedStatement stmt=connection.prepareStatement("SELECT * FROM users WHERE name=?");stmt.setString(1,value);stmt.executeQuery();
 }

}
