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
String p=request.getParameter("path");
// ruleid: ai-security.java.arbitrary-file-read, ai-security.java.file-access
new FileInputStream(p);
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
// ok: ai-security.java.arbitrary-file-read
Files.readString(Paths.get("/srv/data/public.txt"));
}
}
