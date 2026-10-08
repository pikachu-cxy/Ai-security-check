import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
String input=request.getParameter("path"); String guess="ABC"; char selector=guess.charAt(2);
String value; switch(selector) { case 'B': value="fixed"; break; default: value=input; }
new FileOutputStream(new FileInputStream("/srv/data/"+value).getFD());
 }

}
