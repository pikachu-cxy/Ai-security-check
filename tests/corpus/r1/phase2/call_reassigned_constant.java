import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
String sql=request.getParameter("sql");sql="{call fixed_procedure}";connection.prepareCall(sql);
 }

}
