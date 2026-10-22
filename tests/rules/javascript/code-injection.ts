// Synthetic typed handlers. Scan as text; never execute.
import {type Request, type Response} from 'express';
import vm from 'node:vm';
export function evaluate(incoming: Request, outgoing: Response) {
  const text = incoming.body.code;
  const code = `return (${text})`;
  // ruleid: ai-security.javascript.code-injection
  new Function(code);
  // ruleid: ai-security.javascript.code-injection
  vm.runInThisContext(text);
  // ok: ai-security.javascript.code-injection
  vm.runInThisContext('2 + 2');
  // ok: ai-security.javascript.code-injection
  outgoing.json({value: text});
}
export const read = async (req: Request, res: Response) => {
  // ruleid: ai-security.javascript.code-injection
  eval(req.query.expression);
  let safe = req.query.expression;
  safe = '2 + 2';
  // ok: ai-security.javascript.code-injection
  eval(safe);
  // Unknown wrapper return values are outside the local-flow contract.
  const record = directory.lookup(req.cookies.token);
  // ok: ai-security.javascript.code-injection
  eval(record.generatedExpression);
};
function localData(req: {body: {code: string}}) {
  // ok: ai-security.javascript.code-injection
  return eval(req.body.code);
}
