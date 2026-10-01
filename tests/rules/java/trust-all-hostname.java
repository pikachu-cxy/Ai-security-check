import javax.servlet.http.*;
import javax.net.ssl.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ruleid: ai-security.java.trust-all-hostname
HostnameVerifier verifier=(host,session)->true;
}
class TrustAll implements HostnameVerifier {
// ruleid: ai-security.java.trust-all-hostname
    public boolean verify(String host, SSLSession session) { return true; }
}
class VerifyDefault implements HostnameVerifier {
// ok: ai-security.java.trust-all-hostname
    public boolean verify(String host, SSLSession session) {
        return HttpsURLConnection.getDefaultHostnameVerifier().verify(host,session);
    }
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ok: ai-security.java.trust-all-hostname
HostnameVerifier verifier=HttpsURLConnection.getDefaultHostnameVerifier();
}

}
