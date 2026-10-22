package fixtures
import "crypto/tls"
func transport() {
    // ruleid: ai-security.go.tls-verification-disabled
    insecure := &tls.Config{InsecureSkipVerify: true}
    // ok: ai-security.go.tls-verification-disabled
    secure := &tls.Config{InsecureSkipVerify: false}
    // ok: ai-security.go.tls-verification-disabled
    defaults := &tls.Config{}
    _, _, _ = insecure, secure, defaults
}
