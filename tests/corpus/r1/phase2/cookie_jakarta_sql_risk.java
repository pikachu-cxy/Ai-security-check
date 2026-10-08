import jakarta.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
String value=""; Cookie[] cookies=request.getCookies();if(cookies!=null) { for(Cookie cookie:cookies) {value=cookie.getValue();break;} }
Statement stmt=connection.createStatement();stmt.executeQuery("SELECT * FROM users WHERE name='"+value+"'");
 }

}
