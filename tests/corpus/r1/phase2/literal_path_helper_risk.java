import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
String value=select(request.getParameter("x"));new FileInputStream("/srv/data/"+value);
 }
String select(String input) { return input; }
}
