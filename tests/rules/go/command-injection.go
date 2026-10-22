package fixtures
import ("net/http"; "os/exec")
func shell(w http.ResponseWriter, r *http.Request) {
    command := r.URL.Query().Get("command")
    // ruleid: ai-security.go.command-injection
    exec.Command("sh", "-c", command).Run()
    // ruleid: ai-security.go.command-injection
    exec.Command("bash", "-c", r.FormValue("command")).Run()
    // ok: ai-security.go.command-injection
    exec.Command("sh", "-c", "date").Run()
    // ok: ai-security.go.command-injection
    exec.Command("echo", command).Run()
}
