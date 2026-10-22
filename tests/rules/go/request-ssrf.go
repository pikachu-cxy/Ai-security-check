package fixtures
import "net/http"
func fetch(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    // ruleid: ai-security.go.request-ssrf
    http.Get(url)
    // ruleid: ai-security.go.request-ssrf
    http.Post(r.FormValue("url"), "text/plain", nil)
    // ok: ai-security.go.request-ssrf
    http.Get("https://example.com/status")
    // ok: ai-security.go.request-ssrf
    http.Post("https://example.com/events", "text/plain", nil)
}
