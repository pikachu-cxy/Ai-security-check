const https = require("https");
// ruleid: ai-security.javascript.tls-verification-disabled
https.request("https://example.com", {rejectUnauthorized: false});
// ruleid: ai-security.javascript.tls-verification-disabled
new https.Agent({rejectUnauthorized: false});
// ok: ai-security.javascript.tls-verification-disabled
https.request("https://example.com", {rejectUnauthorized: true});
// ok: ai-security.javascript.tls-verification-disabled
new https.Agent({});
