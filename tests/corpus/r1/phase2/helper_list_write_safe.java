import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
String value=select(request.getParameter("path")); new FileOutputStream("/srv/data/"+value);
 }
String select(String input) { List<String> values=new ArrayList<>(); values.add("safe"); values.add(input); values.add("fixed"); values.remove(0); return values.get(1); }
}
