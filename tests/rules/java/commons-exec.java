// Synthetic process definitions; fixtures are parsed, never executed.
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.Executor;

class CommonsExecFixture {
    void dynamicExecutable(HttpServletRequest request, DefaultExecutor executor) throws Exception {
        CommandLine command = CommandLine.parse(request.getParameter("command"));
        // ruleid: ai-security.java.commons-exec
        executor.execute(command);
    }

    void shellSyntax(HttpServletRequest request, Executor executor) throws Exception {
        // ruleid: ai-security.java.commons-exec
        executor.execute(CommandLine.parse("sh -c \"" + request.getParameter("script") + "\""));
    }

    void substitution(HttpServletRequest request, DefaultExecutor executor) throws Exception {
        // ruleid: ai-security.java.commons-exec
        executor.execute(CommandLine.parse(request.getHeader("command"), java.util.Map.of()));
    }

    void fixedArgument(HttpServletRequest request, DefaultExecutor executor) throws Exception {
        CommandLine command = new CommandLine("/usr/bin/printf");
        command.addArgument("%s");
        command.addArgument(request.getParameter("message"), false);
        // ok: ai-security.java.commons-exec
        executor.execute(command);
    }

    void unusedCommand(HttpServletRequest request, DefaultExecutor executor) {
        // ok: ai-security.java.commons-exec
        CommandLine command = CommandLine.parse(request.getParameter("command"));
    }

    void overwrittenCommand(HttpServletRequest request, DefaultExecutor executor) throws Exception {
        // ok: ai-security.java.commons-exec
        CommandLine command = CommandLine.parse(request.getParameter("command"));
        command = CommandLine.parse("/usr/bin/true");
        executor.execute(command);
    }

    void exactSelection(HttpServletRequest request, Executor executor) throws Exception {
        String requested = request.getParameter("action");
        String executable = "/usr/bin/true";
        if ("date".equals(requested)) executable = "/usr/bin/date";
        // ok: ai-security.java.commons-exec
        executor.execute(CommandLine.parse(executable));
    }

    void executedBeforeReplacement(HttpServletRequest request, DefaultExecutor executor) throws Exception {
        CommandLine command = CommandLine.parse(request.getParameter("command"));
        // ruleid: ai-security.java.commons-exec
        executor.execute(command);
        command = CommandLine.parse("/usr/bin/true");
        // ok: ai-security.java.commons-exec
        executor.execute(command);
    }
}
