import javax.servlet.http.HttpServletRequest;
import java.sql.*;
import java.io.*;
import java.net.URL;

class Database {
    void vulnerable(HttpServletRequest request, Connection connection) throws Exception {
        Statement statement = connection.createStatement();
        String query="SELECT * FROM users WHERE name='"+request.getParameter("name")+"'";
        // expected: ai-security.java.jdbc-statement
        statement.executeQuery(query);
        // expected: ai-security.java.file-access
        new FileInputStream(request.getParameter("path"));
        URL url=new URL(request.getParameter("url"));
        // expected: ai-security.java.url-connection
        url.openConnection();
        ObjectInputStream stream=new ObjectInputStream(request.getInputStream());
        // expected: ai-security.java.object-deserialization
        stream.readObject();
    }
    void safe(HttpServletRequest request, Connection connection) throws Exception {
        PreparedStatement statement=connection.prepareStatement("SELECT * FROM users WHERE name=?");
        statement.setString(1,request.getParameter("name"));
        statement.executeQuery();
        new FileInputStream("/srv/trusted/config.txt");
        new URL("https://service.example.invalid/health").openConnection();
        ObjectInputStream stream=new ObjectInputStream(new FileInputStream("/srv/trusted/data.bin"));
        stream.readObject();
    }
}
