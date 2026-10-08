import javax.servlet.http.*;
import java.util.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ruleid: ai-security.java.process-builder
ProcessBuilder builder=new ProcessBuilder(request.getParameter("command"));
builder.start();
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
ProcessBuilder builder=new ProcessBuilder("/usr/bin/id");
// ok: ai-security.java.process-builder
builder.start();
}

void setterRisk(HttpServletRequest request) throws Exception {
ProcessBuilder builder=new ProcessBuilder();
// ruleid: ai-security.java.process-builder
builder.command("sh","-c",request.getParameter("payload"));
builder.start();
}
void setterReplaced(HttpServletRequest request) throws Exception {
ProcessBuilder builder=new ProcessBuilder();
// ok: ai-security.java.process-builder
builder.command(request.getParameter("exec"));
builder.command("/usr/bin/id","-u");
builder.start();
}
void setterListRisk(HttpServletRequest request) throws Exception {
List<String> args=new ArrayList<>();
args.add("sh");args.add("-c");args.add(request.getParameter("payload"));
ProcessBuilder builder=new ProcessBuilder();
// ruleid: ai-security.java.process-builder
builder.command(args);
builder.start();
}
void setterNotStarted(HttpServletRequest request) throws Exception {
ProcessBuilder builder=new ProcessBuilder();
// ok: ai-security.java.process-builder
builder.command(request.getParameter("exec"));
}
void fixedProgramListData(HttpServletRequest request) throws Exception {
List<String> args=new ArrayList<>();
args.add("/usr/bin/printf");args.add("%s");args.add(request.getParameter("data"));
ProcessBuilder builder=new ProcessBuilder();
// ok: ai-security.java.process-builder
builder.command(args);
builder.start();
}
void fixedProgramArrayData(HttpServletRequest request) throws Exception {
String[] args={"/usr/bin/printf","%s",request.getParameter("data")};
ProcessBuilder builder=new ProcessBuilder();
// ok: ai-security.java.process-builder
builder.command(args);
builder.start();
}
}
