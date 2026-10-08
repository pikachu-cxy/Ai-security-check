import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
connection.prepareCall("{call "+request.getParameter("proc")+"}",ResultSet.TYPE_FORWARD_ONLY,ResultSet.CONCUR_READ_ONLY);
 }

}
