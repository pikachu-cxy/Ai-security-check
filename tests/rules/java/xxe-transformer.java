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
TransformerFactory f=TransformerFactory.newInstance();
Transformer p=f.newTransformer();
// ruleid: ai-security.java.xxe-transformer
p.transform(new StreamSource(request.getInputStream()),new StreamResult(new StringWriter()));
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
TransformerFactory f=TransformerFactory.newInstance();
f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,"");
f.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET,"");
Transformer p=f.newTransformer();
// ok: ai-security.java.xxe-transformer
p.transform(new StreamSource(request.getInputStream()),new StreamResult(new StringWriter()));
}
}
