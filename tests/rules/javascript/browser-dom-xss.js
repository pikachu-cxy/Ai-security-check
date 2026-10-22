function render(element) {
    const value = location.hash;
    // ruleid: ai-security.javascript.browser-dom-xss
    element.innerHTML = value;
    // ruleid: ai-security.javascript.browser-dom-xss
    document.write(window.location.search);
    // ok: ai-security.javascript.browser-dom-xss
    element.textContent = value;
    // ok: ai-security.javascript.browser-dom-xss
    element.innerHTML = "<p>Welcome</p>";
}
