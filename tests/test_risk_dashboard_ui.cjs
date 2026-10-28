const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '../src/security_runtime/assets/risk_dashboard.html'), 'utf8');
class Element {
  constructor() { this.value = ''; this.textContent = ''; this.children = []; this.style = {}; this.events = {}; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; }
  addEventListener(name, fn) { this.events[name] = fn; }
}
async function page(data, ok = true) {
  const elements = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(m => [m[1], new Element()]));
  const document = { getElementById: id => elements[id], createElement: () => new Element(), addEventListener() {} };
  const context = vm.createContext({ document, fetch: async () => ({ ok, json: async () => data }) });
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
  await new Promise(resolve => setImmediate(resolve));
  return elements;
}
const risk = (editor, project, status) => ({editor, editor_label: editor === 'cursor' ? 'Cursor' : 'Codex',
  project, status, severity: '高', title: 'Candidate', location: 'api.py:1', category: 'test'});

test('editor, project and status filters update rows and all counters together', async () => {
  const e = await page({partial: false, note: 'Fixture', risks: [
    risk('codex','a','待处理'), risk('cursor','a','AI 排除'), risk('cursor','b','处置未知'),
    risk('cursor','b','已暂缓'), risk('codex','a','已复查')]});
  assert.equal(e.rows.children.length, 5);
  for (const id of ['pending','candidates','excluded','deferred','resolved']) assert.equal(e[id].textContent, 1);
  e.editor.value = 'cursor'; e.editor.events.input();
  assert.equal(e.rows.children.length, 3);
  assert.equal(e.pending.textContent, 0);
  assert.equal(e.excluded.textContent, 1);
  assert.equal(e.rows.children[0].children[1].textContent, 'Cursor');
  e.project.value = 'a'; e.project.events.input();
  assert.equal(e.rows.children.length, 1);
  e.status.value = '待处理'; e.status.events.input();
  assert.equal(e.rows.children.length, 0);
  assert.equal(e.empty.hidden, false);
  e.editor.value = ''; e.project.value = ''; e.status.value = ''; e.editor.events.input();
  assert.equal(e.rows.children.length, 5);
});
test('partial and failed loads are visibly different from a complete empty result', async () => {
  const partial = await page({partial: true, note: 'Cursor：记录不可读取', risks: []});
  assert.match(partial.banner.textContent, /统计不完整/);
  const failed = await page(null, false);
  assert.match(failed.banner.textContent, /不能解释为零风险/);
  assert.equal(failed.count.textContent, '数据读取失败');
});
