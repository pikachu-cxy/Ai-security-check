import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
String input=request.getHeader("proc");String guess="ABC";String value;switch(guess.charAt(1)) {case 'B':value="fixed";break;default:value=input;}connection.prepareCall("{call "+value+"}",ResultSet.TYPE_FORWARD_ONLY,ResultSet.CONCUR_READ_ONLY);
 }

}
