package fixtures
import ("net/http"; "os"; "io/ioutil")
func read(w http.ResponseWriter, r *http.Request) {
    path := r.FormValue("path")
    // ruleid: ai-security.go.request-file-read
    os.ReadFile(path)
    // ruleid: ai-security.go.request-file-read
    ioutil.ReadFile(r.PostFormValue("path"))
    // ok: ai-security.go.request-file-read
    os.ReadFile("/srv/public/help.txt")
    // ok: ai-security.go.request-file-read
    ioutil.ReadFile("/srv/public/help.txt")
}
