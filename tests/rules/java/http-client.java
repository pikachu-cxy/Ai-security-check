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

class Positive {
void check(HttpServletRequest request, Statement statement, Connection connection) throws Exception {
String u=request.getParameter("url");
HttpRequest req=HttpRequest.newBuilder(URI.create(u)).GET().build();
HttpClient client=HttpClient.newHttpClient();
// ruleid: ai-security.java.http-client
client.send(req,HttpResponse.BodyHandlers.ofString());
}
}

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

class Negative {
void check(HttpServletRequest request, Statement statement, Connection connection) throws Exception {
String ignored=request.getParameter("url");
// ok: ai-security.java.http-client
new URL("https://example.test/api").openConnection();
}
}
