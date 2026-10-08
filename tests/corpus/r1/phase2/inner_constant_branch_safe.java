import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
String value=new Helper().select(request.getHeader("path")); new FileOutputStream("/srv/data/"+value);
 }
private class Helper { String select(String input) { int n=86; if ((7*42)-n>200) return "fixed"; else return input; }}
}
