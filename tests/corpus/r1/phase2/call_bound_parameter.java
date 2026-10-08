import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
CallableStatement stmt=connection.prepareCall("{call fixed_procedure(?)}");stmt.setString(1,request.getParameter("name"));stmt.execute();
 }

}
