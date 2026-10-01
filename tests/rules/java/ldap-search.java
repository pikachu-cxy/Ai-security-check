import javax.servlet.http.*;
import javax.naming.directory.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
DirContext context=null;
String filter="(uid="+request.getParameter("name")+")";
// ruleid: ai-security.java.ldap-search
context.search("ou=users",filter,new SearchControls());
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
DirContext context=null;
// ok: ai-security.java.ldap-search
context.search("ou=users","(uid={0})",new Object[]{request.getParameter("name")},new SearchControls());
}

}
