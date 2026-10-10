// Synthetic outbound HTTP examples; no network request is executed by the rule gate.
import javax.servlet.http.HttpServletRequest;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;

class ApacheHttpFixture {
    static class OtherService {
        void execute(HttpGet value) { }
    }

    void unrelatedExecute(HttpServletRequest request, OtherService service) {
        // ok: ai-security.java.apache-httpclient
        service.execute(new HttpGet(request.getParameter("url")));
    }

    void localRequest(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        HttpGet outbound = new HttpGet(request.getParameter("url"));
        // ruleid: ai-security.java.apache-httpclient
        client.execute(outbound);
    }

    void inlineRequest(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        // ruleid: ai-security.java.apache-httpclient
        client.execute(new HttpPost(request.getHeader("callback")));
    }

    void modernRequest(jakarta.servlet.http.HttpServletRequest request, org.apache.hc.client5.http.impl.classic.CloseableHttpClient client) throws Exception {
        org.apache.hc.client5.http.classic.methods.HttpGet outbound = new org.apache.hc.client5.http.classic.methods.HttpGet(request.getParameter("url"));
        // ruleid: ai-security.java.apache-httpclient
        client.execute(outbound, response -> null);
    }

    void fixedDestinationWithHeader(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        HttpGet outbound = new HttpGet("https://example.test/api");
        outbound.setHeader("X-Trace", request.getParameter("trace"));
        // ok: ai-security.java.apache-httpclient
        client.execute(outbound);
    }

    void fixedDestinationWithBody(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        HttpPost outbound = new HttpPost("https://example.test/api");
        outbound.setEntity(new org.apache.http.entity.StringEntity(request.getParameter("body")));
        // ok: ai-security.java.apache-httpclient
        client.execute(outbound);
    }

    void unusedRequest(HttpServletRequest request) {
        // ok: ai-security.java.apache-httpclient
        HttpGet outbound = new HttpGet(request.getParameter("url"));
    }

    void replacedRequest(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        // ok: ai-security.java.apache-httpclient
        HttpGet outbound = new HttpGet(request.getParameter("url"));
        outbound = new HttpGet("https://example.test/api");
        client.execute(outbound);
    }

    void exactAllowlist(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        String requested = request.getParameter("service");
        String endpoint = "https://one.example.test/api";
        if ("two".equals(requested)) endpoint = "https://two.example.test/api";
        // ok: ai-security.java.apache-httpclient
        client.execute(new HttpGet(endpoint));
    }

    void executedBeforeReplacement(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        HttpGet outbound = new HttpGet(request.getParameter("url"));
        // ruleid: ai-security.java.apache-httpclient
        client.execute(outbound);
        outbound = new HttpGet("https://example.test/api");
        // ok: ai-security.java.apache-httpclient
        client.execute(outbound);
    }

    void destinationSetter(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        HttpGet outbound = new HttpGet("https://example.test/api");
        outbound.setURI(java.net.URI.create(request.getParameter("url")));
        // ruleid: ai-security.java.apache-httpclient
        client.execute(outbound);
    }

    void modernDestinationSetter(jakarta.servlet.http.HttpServletRequest request, org.apache.hc.client5.http.impl.classic.CloseableHttpClient client) throws Exception {
        org.apache.hc.client5.http.classic.methods.HttpPost outbound = new org.apache.hc.client5.http.classic.methods.HttpPost("https://example.test/api");
        outbound.setUri(java.net.URI.create(request.getParameter("url")));
        // ruleid: ai-security.java.apache-httpclient
        client.execute(outbound, response -> null);
    }

    void fixedDestinationSetter(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        HttpGet outbound = new HttpGet(request.getParameter("url"));
        outbound.setURI(java.net.URI.create("https://example.test/api"));
        // ok: ai-security.java.apache-httpclient
        client.execute(outbound);
    }

    void destinationTaintReintroduced(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        HttpGet outbound = new HttpGet(request.getParameter("url"));
        outbound.setURI(java.net.URI.create("https://example.test/api"));
        outbound.setURI(java.net.URI.create(request.getParameter("nextUrl")));
        // ruleid: ai-security.java.apache-httpclient
        client.execute(outbound);
    }

    void invalidFixedUriCaught(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        HttpGet outbound = new HttpGet(request.getParameter("url"));
        try {
            outbound.setURI(java.net.URI.create("invalid uri with spaces"));
        } catch (IllegalArgumentException ignored) {
            // URI construction failed before setURI; the original destination remains.
        }
        // ruleid: ai-security.java.apache-httpclient
        client.execute(outbound);
    }

    void fixedDestinationNewUri(HttpServletRequest request, CloseableHttpClient client) throws Exception {
        HttpGet outbound = new HttpGet(request.getParameter("url"));
        outbound.setURI(new java.net.URI("https://example.test/api"));
        // ok: ai-security.java.apache-httpclient
        client.execute(outbound);
    }

    void modernFixedDestinationSetter(jakarta.servlet.http.HttpServletRequest request, org.apache.hc.client5.http.impl.classic.CloseableHttpClient client) throws Exception {
        org.apache.hc.client5.http.classic.methods.HttpPost outbound = new org.apache.hc.client5.http.classic.methods.HttpPost(request.getParameter("url"));
        outbound.setUri(java.net.URI.create("https://example.test/api"));
        // ok: ai-security.java.apache-httpclient
        client.execute(outbound, response -> null);
    }
}
