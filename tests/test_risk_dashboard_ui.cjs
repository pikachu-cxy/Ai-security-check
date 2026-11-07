const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../src/security_runtime/assets/risk_dashboard.html'),'utf8');
class Element {
 constructor(tag='div'){this.tag=tag;this.value='';this.textContent='';this.children=[];this.style={};this.dataset={};this.checked=false;this.classList={add:()=>{},remove:()=>{},toggle:()=>{}}}
 append(...v){this.children.push(...v)} replaceChildren(...v){this.children=v} focus(){} addEventListener(n,fn){this['on'+n]=fn}
 querySelectorAll(selector){return this.children.flatMap(c=>[...((c.tag==='input'||c.tag==='select')?[c]:[]),...c.querySelectorAll(selector)])}
}
const row={id:'risk1',title:'<script>unsafe</script>',editor:'codex',editor_label:'Codex',project:'project',location:'query.py:2',severity:'高',status:'待处理',editable:true,revision:'revision',description:'description'};
async function page({search='',result,post,get}={}){
 const els=Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Element()]));
 els.archived.value='false';const requests=[];
 const document={getElementById:id=>els[id],createElement:tag=>new Element(tag),querySelectorAll:()=>[],addEventListener(){}};
 const ctx=vm.createContext({document,URLSearchParams,Date,Set,crypto:{randomUUID:()=> 'request-0001'},structuredClone,
   window:{location:{search,assign:url=>requests.push(url)}},history:{replaceState(){}},setTimeout:()=>{},
   fetch:async(url,options)=>{requests.push({url,options});return {ok:true,json:async()=>url==='/api/session'?{csrf:'fixture-token'}:options?.method==='POST'?(post||{results:[]}):(get?.(url)||result||{status:'AVAILABLE',risks:[row],total:5000,partial:false,note:'fixture',statistics:{status:{待处理:5000},editor:{codex:5000}}})}}});
 vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1],ctx);
 await new Promise(resolve=>setImmediate(resolve));return {els,requests,ctx};
}
test('session/worktree links survive in server-side filters and counts use all matching rows',async()=>{
 const {els,requests}=await page({search:'?project=project&workspace=work&session=chat&editor=codex'});
 const url=new URL(requests[1].url,'http://localhost');assert.equal(url.searchParams.get('workspace'),'work');assert.equal(url.searchParams.get('session'),'chat');
 assert.equal(els.pending.textContent,5000);assert.equal(els.rows.children.length,1);assert.match(els.count.textContent,/5000/);
 assert.equal(els.rows.children[0].children[1].children[0].textContent,'<script>unsafe</script>');
});
test('batch updates use expected revision, anti-CSRF and show partial failures',async()=>{
 const {els,requests}=await page({post:{results:[{id:'risk1',saved:false,error:'VERSION_CONFLICT'}]}});
 els.rows.children[0].children[0].children[0].checked=true;els.rows.children[0].children[0].children[0].onchange();
 els.batchAction.value='DEFER';els.batchReason.value='Later';els.batchSave.onclick();await new Promise(resolve=>setImmediate(resolve));
 const request=requests.find(r=>r.url==='/api/actions');assert.equal(request.options.headers['X-CSRF-Token'],'fixture-token');
 const body=JSON.parse(request.options.body);assert.equal(body.items[0].request.expected_revision,'revision');assert.equal(body.items[0].request.reason,'Later');
 assert.match(els.message.textContent,/1 项未保存/);
});
test('unavailable index never displays a complete empty result',async()=>{
 const {els}=await page({result:{status:'UNAVAILABLE',risks:[],partial:true,note:'Cannot load'}});
 assert.equal(els.count.textContent,'数据不可用');assert.match(els.banner.textContent,/统计不完整/);
});
test('dashboard separates confirmed counts and renders category share rings',async()=>{
 const {els}=await page({result:{status:'AVAILABLE',risks:[row],total:3,note:'fixture',statistics:{},finding_metrics:{scanner:{total:3,categories:{sql:2,secret:1}},confirmed:{total:1,categories:{sql:1}}}}});
 assert.equal(els.scannerTotal.textContent,3);assert.equal(els.confirmedTotal.textContent,1);
 const scan=els.categoryMetrics.children[0];const real=els.categoryMetrics.children[1];
 assert.match(scan.children[1].style.background,/conic-gradient/);
 assert.equal(scan.children[2].children[1].textContent,'2 · 66.7%');
 assert.equal(real.children[2].children[1].textContent,'1 · 100.0%');
 assert.equal(els.check,undefined);
});
test('history diagnostics expose the affected scope and distinguish indexing from failure',async()=>{
 const {els}=await page({result:{status:'AVAILABLE',risks:[],total:0,partial:true,note:'签名校验失败',diagnostics:[{message:'签名校验失败',editor:'codex',workspace_id:'fixture-workspace',database:'development-records'}]}});
 assert.equal(els.historyDiagnostics.hidden,false);
 assert.match(els.historyIssues.children[0].textContent,/fixture-workspace/);
 const building=await page({result:{status:'BUILDING',partial:true,note:'正在载入已保存记录'}});
 assert.match(building.els.banner.textContent,/历史索引尚未完成/);
 assert.doesNotMatch(building.els.banner.textContent,/统计不完整/);
 const missingRoot=await page({result:{status:'AVAILABLE',risks:[],total:0,partial:false,note:'原项目目录已不存在；历史记录已载入'}});
 assert.doesNotMatch(missingRoot.els.banner.textContent,/统计不完整/);
});

const tick=()=>new Promise(resolve=>setImmediate(resolve));
test('project to worktree to session navigation isolates siblings and risk filters',async()=>{
 const parent=(p,w,editor='codex')=>({project_id:p,workspace_id:w,editor,workspace:'/'+w});
 const entity=(kind,id,scope,parents)=>({kind,id,name:id,scope,parents,risk_count:1,session_count:1,workspace_count:2});
 const project=entity('project','project-p',{project_id:'p'},[parent('p','w1'),parent('p','w2')]);
 const ws=[entity('workspace','w1',{workspace_id:'w1',editor:'codex'},[parent('p','w1')]),entity('workspace','w2',{workspace_id:'w2',editor:'codex'},[parent('p','w2')]),entity('workspace','other',{workspace_id:'w3',editor:'codex'},[parent('other','w3')])];
 const chats=ws.map(w=>entity('session','session-'+w.id,{...w.scope,session_id:'shared-session'},w.parents));
 const {ctx,els,requests}=await page({get:url=>url.includes('/api/entities?kind=')?{items:({project:[project],workspace:ws,session:chats})[url.split('=').pop()]}:null});
 vm.runInContext("resourceNavigate('project')",ctx);await tick();
 els.entityRows.children[0].children[0].children[0].onclick();await tick();
 assert.equal(els.pageTitle.textContent,'工作区管理');assert.equal(els.entityRows.children.length,2);assert.equal(els.entityProject.value,'p');
 els.entityRows.children[0].children[0].children[0].onclick();await tick();
 assert.equal(els.pageTitle.textContent,'会话管理');assert.equal(els.entityRows.children.length,1);
 els.entityRows.children[0].children[3].children[0].children[0].onclick();await tick();
 const query=new URL(requests.filter(r=>r.url?.startsWith('/api/risks?')).at(-1).url,'http://localhost').searchParams;
 assert.equal(query.get('project'),'p');assert.equal(query.get('workspace'),'w1');assert.equal(query.get('editor'),'codex');assert.equal(query.get('session'),'shared-session');
 vm.runInContext("resourceNavigate('workspace')",ctx);await tick();assert.equal(els.entityRows.children.length,2);
 els.entityProject.value='other';els.entityProject.onchange();assert.equal(els.entityRows.children.length,1);
 vm.runInContext("resourceNavigate('project')",ctx);await tick();assert.equal(els.entityContext.hidden,true);
});
test('collapsible functional settings preserve all values and save nested typed changes',async()=>{
 const values={schema_version:1,agent:{review_scanner_findings:true,audit_business_logic:false},development:{business_audit_delivery:'fast',stop_fallback:{enabled:true,wait_timeout_seconds:120}},scan:{execution:{sast_timeout_seconds:45},dataflow:{max_steps:100}},rules:{sast:{mode:'builtin',paths:[],exclude_ids:[]}},vulnerability_data:{trivy:{update_mode:'auto'}},storage:{development_max_records:1024}};
 const {els,requests}=await page({get:url=>url==='/api/config'?{values,revision:'settings-v1'}:null,post:{values,revision:'settings-v2'}});
 await els.settingsOpen.onclick();
 assert.equal(els.configFields.children.length,6);assert.ok(els.configFields.children.every(e=>e.tag==='details'&&!e.open));
 const fields=els.configFields.querySelectorAll('input,select');assert.equal(new Set(fields.map(e=>e.dataset.path)).size,fields.length);
 fields.find(e=>e.dataset.path==='agent.audit_business_logic').checked=true;
 fields.find(e=>e.dataset.path==='scan.execution.sast_timeout_seconds').value='60';
 fields.find(e=>e.dataset.path==='development.business_audit_delivery').value='wait';
 await els.configSave.onclick();
 const saved=JSON.parse(requests.find(r=>r.url==='/api/config'&&r.options?.method==='POST').options.body);
 assert.equal(saved.expected_revision,'settings-v1');assert.equal(saved.values.agent.audit_business_logic,true);assert.equal(saved.values.scan.execution.sast_timeout_seconds,60);assert.equal(saved.values.development.business_audit_delivery,'wait');assert.equal(saved.values.storage.development_max_records,1024);assert.deepEqual(saved.values.rules.sast.paths,[]);
});
test('detail loads code only on open and exposes four report sections before folded metadata',async()=>{
 const saved={...row,decision:'CONFIRMED',report_text:'**SQL injection**\n评级：高\n**问题**\nUnsafe SQL\n**可能影响**\nRead data\n**建议修复**\nBind parameters\n**尚未确认**\nDeployment',management:{}};
 const code={absolute_path:'/fixture/query.py',line_start:2,function:'query',historical:null,current:{matches_record:true,label:'当前代码（与记录版本一致）',lines:[{number:2,text:'<img onerror=alert(1)>',highlight:true}]}};
 const {ctx,els,requests}=await page({get:url=>url.startsWith('/api/detail?')?code:null});
 assert.ok(!requests.some(r=>r.url?.startsWith('/api/detail?')));
 ctx.risk=saved;await vm.runInContext('detail(risk)',ctx);
 assert.equal(els.detailTitle.textContent,'SQL injection');
 assert.equal(els.detailBody.children[1].children[1].textContent,'Unsafe SQL');
 assert.equal(els.detailBody.children.at(-1).tag,'details');
 assert.equal(els.detailBody.children[0].children[3].children[0].children[1].textContent,'<img onerror=alert(1)>');
 assert.equal(els.repair.disabled,false);assert.equal(els.repair.textContent,'交给原会话修复');
 assert.match(requests.find(r=>r.url?.startsWith('/api/detail?')).url,/revision=revision/);
});
test('repair controls show actual ownership and prohibit duplicate or resolved handoffs',async()=>{
 const {ctx,els}=await page();
 for(const [state,label,disabled] of [['AWAITING_HOST','等待原会话继续',true],['PREPARED','修复处理中',true],['FAILED','重试交接',false],['NEEDS_REVIEW','重试交接',false],['CANCELLED','重试交接',false]]){
  ctx.risk={...row,decision:'CONFIRMED',management:{repair_request:{status:state}}};vm.runInContext('repairControls(risk)',ctx);
  assert.equal(els.repair.textContent,label);assert.equal(els.repair.disabled,disabled);assert.equal(els.cancelRepair.hidden,state!=='AWAITING_HOST');
 }
 ctx.risk={...row,decision:'CONFIRMED',status:'CODE_REVIEWED_RESOLVED'};vm.runInContext('repairControls(risk)',ctx);assert.equal(els.repair.disabled,true);assert.match(els.repairState.textContent,/不代表扫描器验证/);
 ctx.risk={...row,decision:'DISMISSED'};vm.runInContext('repairControls(risk)',ctx);assert.equal(els.repair.disabled,true);
});

test('review response budget belongs to product settings and preserves its numeric value',async()=>{
 const {ctx,els}=await page();
 vm.runInContext("configForm({development:{review_response_bytes:65536}})",ctx);
 const input=els.configFields.querySelectorAll('input').find(i=>i.dataset.path==='development.review_response_bytes');
 assert.equal(input.value,65536);assert.equal(input.dataset.kind,'number');
 assert.equal(input.min,'16384');assert.equal(input.max,'262144');
});
