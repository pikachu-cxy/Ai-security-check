import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
Other api=new Other();api.prepareCall(request.getParameter("sql"));
 }
class Other { void prepareCall(String text) {} }
}
