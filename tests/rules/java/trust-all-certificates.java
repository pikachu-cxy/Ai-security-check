import javax.servlet.http.*;
import javax.net.ssl.*;
import java.security.cert.*;

class Fixture {
void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ruleid: ai-security.java.trust-all-certificates
X509TrustManager trust=new X509TrustManager() { public void checkServerTrusted(X509Certificate[] chain,String auth) {} public void checkClientTrusted(X509Certificate[] chain,String auth) {} public X509Certificate[] getAcceptedIssuers() {return new X509Certificate[0];} };
}
void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
// ok: ai-security.java.trust-all-certificates
X509TrustManager trust=new X509TrustManager() { public void checkServerTrusted(X509Certificate[] chain,String auth) throws CertificateException {throw new CertificateException("rejected");} public void checkClientTrusted(X509Certificate[] chain,String auth) throws CertificateException {throw new CertificateException("rejected");} public X509Certificate[] getAcceptedIssuers() {return new X509Certificate[0];} };
}

}
