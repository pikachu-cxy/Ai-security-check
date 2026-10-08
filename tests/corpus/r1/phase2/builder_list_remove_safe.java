import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
List<String> args=new ArrayList<>();args.add(request.getParameter("exec"));args.add("/usr/bin/id");args.remove(0);ProcessBuilder builder=new ProcessBuilder();builder.command(args);builder.start();
 }

}
