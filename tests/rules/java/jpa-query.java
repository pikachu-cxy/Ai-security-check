// Synthetic JPA/Hibernate templates. Criteria and named-query APIs are not string sinks.
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestParam;

class JpaQueryFixture {
    void legacy(HttpServletRequest request, javax.persistence.EntityManager em) {
        // ruleid: ai-security.java.jpa-query
        em.createQuery("SELECT a FROM Account a WHERE a.name='" + request.getParameter("name") + "'");
    }

    void nativeQuery(HttpServletRequest request, jakarta.persistence.EntityManager em) {
        // ruleid: ai-security.java.jpa-query
        em.createNativeQuery("SELECT id FROM accounts ORDER BY " + request.getParameter("sort"));
    }

    void typed(@RequestParam("name") String name, jakarta.persistence.EntityManager em) {
        // ruleid: ai-security.java.jpa-query
        em.createQuery("SELECT a FROM Account a WHERE a.name='" + name + "'", Object.class);
    }

    void hibernate(HttpServletRequest request, org.hibernate.Session session) {
        // ruleid: ai-security.java.jpa-query
        session.createSelectionQuery("FROM Account WHERE name='" + request.getHeader("name") + "'", Object.class);
    }

    void nativeMutation(HttpServletRequest request, org.hibernate.Session session) {
        // ruleid: ai-security.java.jpa-query
        session.createNativeMutationQuery("DELETE FROM accounts WHERE id=" + request.getParameter("id"));
    }

    void boundJpql(HttpServletRequest request, jakarta.persistence.EntityManager em) {
        // ok: ai-security.java.jpa-query
        em.createQuery("SELECT a FROM Account a WHERE a.name=:name").setParameter("name", request.getParameter("name"));
    }

    void boundNative(HttpServletRequest request, javax.persistence.EntityManager em) {
        // ok: ai-security.java.jpa-query
        em.createNativeQuery("SELECT id FROM accounts WHERE name=?1").setParameter(1, request.getParameter("name"));
    }

    void namedSelection(HttpServletRequest request, jakarta.persistence.EntityManager em) {
        // ok: ai-security.java.jpa-query
        em.createNamedQuery(request.getParameter("queryName"));
    }

    void fixedHibernate(HttpServletRequest request, org.hibernate.Session session) {
        String ignored = request.getParameter("name");
        // ok: ai-security.java.jpa-query
        session.createMutationQuery("DELETE FROM Account WHERE expired=true");
    }
}
