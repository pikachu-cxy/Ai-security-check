import javax.servlet.http.*;
import java.io.*;
import java.sql.*;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import javax.net.ssl.*;
import javax.xml.parsers.*;
import javax.xml.stream.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.*;
import javax.xml.XMLConstants;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

class Fixture {
void check(HttpServletRequest request, Statement statement, Connection connection) throws Exception {
Runtime.getRuntime().exec(request.getParameter("cmd"));
}
}
