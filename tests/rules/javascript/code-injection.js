// Synthetic request-to-code boundaries. Scan as text; never execute.
const express = require('express');
const vm = require('node:vm');
const app = express();
app.post('/evaluate', (request, response) => {
  const input = request.body.expression;
  const code = 'return (' + input + ')';
  // ruleid: ai-security.javascript.code-injection
  eval(input);
  // ruleid: ai-security.javascript.code-injection
  new Function('value', code);
  // ruleid: ai-security.javascript.code-injection
  Function(code);
  // ruleid: ai-security.javascript.code-injection
  vm.runInNewContext(input, {}, {timeout: 10});
  // ok: ai-security.javascript.code-injection
  vm.runInNewContext('input', {input});
  // ok: ai-security.javascript.code-injection
  eval('2 + 2');
  // ok: ai-security.javascript.code-injection
  JSON.parse(input);
  let reset = input;
  reset = '2 + 2';
  // ok: ai-security.javascript.code-injection
  eval(reset);
  // Opaque return values have no established local code-input path.
  const record = directory.lookup(request.cookies.token);
  // ok: ai-security.javascript.code-injection
  eval(record.generatedExpression);
});
function Handler() {
  this.update = (incoming, outgoing, next) => {
    // ruleid: ai-security.javascript.code-injection
    const value = eval(incoming.body.value);
    outgoing.json({value});
  };
}
function unrelated(req) {
  // ok: ai-security.javascript.code-injection
  return eval(req.body.expression);
}
function NonWeb() {
  this.compute = (data, options) => {
    // ok: ai-security.javascript.code-injection
    return eval(data.body.expression);
  };
}
