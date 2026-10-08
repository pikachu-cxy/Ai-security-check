import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
String input=request.getParameter("exec");ProcessBuilder builder=new ProcessBuilder();builder.command(input);builder.command("/usr/bin/id");builder.command(input);builder.start();
 }

}
