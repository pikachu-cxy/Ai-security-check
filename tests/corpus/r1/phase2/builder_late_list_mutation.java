import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
class Example {
 void handle(HttpServletRequest request, Connection connection) throws Exception {
List<String> args=new ArrayList<>();args.add("sh");args.add("-c");ProcessBuilder builder=new ProcessBuilder();builder.command(args);args.add(request.getParameter("payload"));builder.start();
 }

}
