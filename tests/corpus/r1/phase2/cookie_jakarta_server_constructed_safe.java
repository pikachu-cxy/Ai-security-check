import jakarta.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
Cookie cookie=new Cookie("path","/srv/data/fixed");new FileInputStream(cookie.getValue());
 }

}
