import javax.servlet.http.*;
import java.sql.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
Statement stmt=connection.createStatement();
String sql="SELECT * FROM users WHERE name='"+request.getParameter("name")+"'";
// ruleid: ai-security.java.jdbc-statement
stmt.executeQuery(sql);
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
PreparedStatement stmt=connection.prepareStatement("SELECT * FROM users WHERE name=?");
stmt.setString(1,request.getParameter("name"));
// ok: ai-security.java.jdbc-statement
stmt.executeQuery();
}
java.sql.Connection connection;

void callableRisk(HttpServletRequest request) throws Exception {
String sql="{call "+request.getParameter("procedure")+"(?)}";
// ruleid: ai-security.java.jdbc-statement
CallableStatement stmt=connection.prepareCall(sql);
stmt.setString(1,request.getParameter("value"));
stmt.execute();
}
void callableBoundValue(HttpServletRequest request) throws Exception {
// ok: ai-security.java.jdbc-statement
CallableStatement stmt=connection.prepareCall("{call fixed_procedure(?)}");
stmt.setString(1,request.getParameter("value"));
stmt.execute();
}
}
