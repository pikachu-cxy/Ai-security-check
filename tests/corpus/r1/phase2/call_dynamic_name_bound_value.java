import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
CallableStatement stmt=connection.prepareCall("{call "+request.getParameter("proc")+"(?)}"); stmt.setString(1,request.getParameter("value"));stmt.execute();
 }

}
