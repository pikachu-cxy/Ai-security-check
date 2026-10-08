import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
String value=select(request.getParameter("name")); Statement stmt=connection.createStatement(); stmt.executeQuery("SELECT * FROM users WHERE name='"+value+"'");
 }
String select(String input) { String guess="ABC"; switch(guess.charAt(1)) { case 'B': return "fixed"; default: return input; }}
}
