"""Shared metadata-only DOM renderer for live and offline observation views."""
SCRIPT = r'''
function renderModelDetails(data, parent){
 const el=(tag,value)=>{const n=document.createElement(tag);n.textContent=value;return n},num=n=>n==null?'未知':Number(n).toLocaleString('zh-CN');
 let panel=document.getElementById('modelEvidence');if(!panel){panel=el('section','');panel.id='modelEvidence';panel.className='panel';parent.appendChild(panel)}panel.replaceChildren();
 panel.appendChild(el('h2','模型请求与输入构成'));
 const m=data.model_requests||{requests:[]};
 panel.appendChild(el('p','BYOK 已保留 '+num(m.observed_attempts)+' 次请求尝试；有用量 '+num(m.reported_attempts)+' 次，未完成 '+num(m.pending_attempts)+' 次。已知请求 token 合计 '+num(m.reported_usage&&m.reported_usage.total_tokens)+'；与宿主累计用量分开，不相加。'));
 panel.appendChild(el('p','输入组成按实际客户端消息的 UTF-8 字节记录，不是 token 分摊。服务端包装未知；重复内容只表示本进程保留记录中曾观察到，不等于缓存命中。'));
 const labels={system_instructions:'系统指令',developer_instructions:'开发者指令',user_input:'用户输入',repository_evidence:'仓库证据',related_evidence:'关联证据',product_evidence:'产品证据与元数据',output_schema:'输出结构约束',json_framing:'JSON 结构',history:'历史回复',assistant_history:'助手历史',tool_results:'工具结果',tool_call_arguments:'工具调用参数',unknown:'未知来源'};
 for(const r of (m.requests||[]).slice(-100).reverse()){
  const d=el('details','');d.appendChild(el('summary','请求 '+r.request_id.slice(0,12)+' · '+r.state+' · token '+num(r.usage&&r.usage.total_tokens)));
  d.appendChild(el('p','父调用 '+(r.parent_call_id||'无')+'；'+(r.links||[]).map(x=>x.subject+' / '+x.relation).join('；')));
  d.appendChild(el('p','实际请求体 '+num(r.input.request_bytes)+' B；消息内容 '+num(r.input.content_bytes)+' B；缓存输入 '+num(r.usage&&r.usage.cached_input_tokens)+' token；推理输出 '+num(r.usage&&r.usage.reasoning_output_tokens)+' token。'));
  const table=el('table','');for(const c of r.input.components){const tr=el('tr','');for(const value of [labels[c.category]||c.category,c.role,num(c.bytes)+' B',c.reuse==='PREVIOUSLY_OBSERVED'?'已观察过':'首次观察'])tr.appendChild(el('td',value));table.appendChild(tr)}d.appendChild(table);panel.appendChild(d)
 }
 const visible=data.host&&data.host.visible_context;
 if(visible){panel.appendChild(el('h2','宿主可见输入片段'));panel.appendChild(el('p','以下来自已选择聊天的可见日志片段，不能证明某次模型最终采用的输入、历史携带或 token。隐藏指令、压缩与裁剪保持未知。'));for(const input of (visible.inputs||[]).slice(-10).reverse()){const d=el('details','');d.appendChild(el('summary','可见片段 '+input.input_index+' · '+num(input.items)+' 条消息/工具项目'));for(const c of input.components)d.appendChild(el('p',(labels[c.category]||c.category)+'：'+num(c.text_bytes)+' B，非文本部分 '+num(c.media_parts)));panel.appendChild(d)}}
 const outcomes=(data.associations||{}).product_outcomes||[];
 if(outcomes.length){const d=el('details','');d.appendChild(el('summary','产品结果的调用关联（最近最多 100 条）'));for(const o of outcomes.slice(0,100))d.appendChild(el('p',o.kind+' · '+o.subject+' · 父调用 '+(o.parent_call_id||'未观测')+' · '+o.links.map(x=>x.subject+' / '+x.relation).join('；')));panel.appendChild(d)}
 const health=data.collector_health||{producers:[]};panel.appendChild(el('h2','采集检查点'));
 panel.appendChild(el('p','检查点是采集进程累计水位，独立于当前聊天或运行筛选；停滞可能表示进程退出或存储阻塞。最后检查点之后仍可能缺失，产品不会等待监控排空。'));
 for(const p of health.producers||[])panel.appendChild(el('p',p.producer+' · '+p.state+' · 待完成 '+num(p.pending)+' · 丢弃 '+num(p.dropped)+' · 写入失败 '+num(p.write_errors)));
}
'''

# One shared renderer keeps the live console and exported report on the same
# counting and coverage contract. It consumes metadata only and has no I/O.
SCRIPT += r'''
function renderModelEvidence(data,parent){
 const el=(tag,value='')=>{const n=document.createElement(tag);n.textContent=value;return n};
 const num=n=>n==null?'未知':Number(n).toLocaleString('zh-CN'),list=v=>Array.isArray(v)?v:[];
 const words={COMPLETED:'已完成',PARTIAL:'部分完成',FAILED:'执行失败',NOT_RUN:'未执行',UNKNOWN:'状态未知',IN_PROGRESS:'进行中',
  EXECUTED:'已执行',OBSERVED:'已观测',SUCCESS:'执行成功',UNAVAILABLE:'暂不可用',NOT_COVERED:'未覆盖',
  NOT_APPLICABLE:'不适用',PLANNED:'尚未执行',SKIPPED:'已跳过',DISABLED:'未启用',PENDING:'等待完成',
  NOT_PROVIDED:'未提供',UNSUPPORTED:'尚不支持',FULL:'已覆盖选定范围',COMPLETE:'已覆盖选定范围',
  COVERED:'已覆盖选定范围',ENABLED:'已启用',AVAILABLE:'已就绪',CANCELLED:'已取消',TIMED_OUT:'执行超时',
  TIMEOUT:'执行超时',NO_CHANGES:'没有待检查变更',SCOPED:'限定范围',MINIMAL:'少量范围',NONE:'未覆盖',NOT_STARTED:'尚未开始',RUNNING:'进行中'};
 const status=v=>words[v]||'状态未知';
 const languages={python:'Python',java:'Java',javascript:'JavaScript',typescript:'TypeScript',vue:'Vue',
  go:'Go',php:'PHP',ruby:'Ruby',rust:'Rust',c:'C',cpp:'C++',csharp:'C#',kotlin:'Kotlin',swift:'Swift',scala:'Scala',
  html:'HTML',xml:'XML',yaml:'YAML',json:'JSON',dockerfile:'Dockerfile',terraform:'Terraform',other:'其他语言'};
 const capabilities={sast:'代码规则检查',code:'代码检查',secret:'密钥检查',secrets:'密钥检查',dependency:'依赖检查',
  dependencies:'依赖检查',configuration:'配置检查',ai:'AI 分析',semgrep:'代码规则引擎',gitleaks:'密钥检查',
  osv:'依赖检查',native:'原生代码检查','bounded-dataflow':'有界数据流','native-dataflow':'有界数据流','go-sql':'Go SQL 数据流',
  CODE_SAST:'代码规则检查',SECRET_SCAN:'密钥检查',DEPENDENCY_VULN:'依赖漏洞',IAC_MISCONFIG:'基础设施配置',
  CONTAINER_VULN:'容器漏洞',LICENSE_SCAN:'许可证',SBOM:'软件物料清单',PACKAGE_RISK:'软件包风险',
  AI_SKILL_SECURITY:'AI 技能安全',MCP_SECURITY_STATIC:'MCP 静态检查',MCP_SECURITY_DYNAMIC:'MCP 动态检查',
  AGENT_DYNAMIC_SECURITY:'智能体动态检查',AI_INFRA_VULN:'AI 基础设施',LLM_JAILBREAK:'模型越狱检查',
  MODEL_API_INTEGRITY:'模型接口完整性',AGENT_RUNTIME_SECURITY:'智能体运行安全',AI_APP_SECURITY:'AI 应用安全',OTHER:'其他检查能力'};
 const reasons={
  NO_SCAN_OBSERVATIONS:['没有保留的检查结果','启用观测后，按原有方式主动发起检查；本页面不会代为扫描。'],
  NO_STABLE_IDENTITIES:['缺少可跨扫描去重的问题标识','查看原检查报告，待处理总量保持未知。'],
  MISSING_STABLE_IDENTITIES:['部分问题缺少可跨扫描去重的标识','已观测数量仅覆盖保留的问题身份。'],
  FINDING_IDENTITIES_INCOMPLETE:['逐条问题标识不完整','不能将保留数量当作完整待处理总量。'],
  FINDING_DETAILS_OMITTED:['部分问题明细超过保留上限','累计发现仍按扫描计数，去重只覆盖保留明细。'],
  OMITTED_FINDINGS:['部分问题明细超过保留上限','累计发现仍按扫描计数，去重只覆盖保留明细。'],
  VERIFICATION_RECORDS_LIMITED:['部分复验记录超过保留上限','未保留的处置状态不能推断为已解决。'],
  LEGACY_SCAN_WITHOUT_CHECK_EVIDENCE:['旧记录缺少检查完成证据','历史发现仍保留，检查状态不能补记为完成。'],
  LEGACY_CHECK_EVIDENCE_MISSING:['旧记录缺少检查完成证据','历史发现仍保留，检查状态不能补记为完成。'],
  SCANNER_FAILED:['扫描器执行失败','查看原检查报告中的失败步骤，处理后主动重试。'],
  SCANNER_UNAVAILABLE:['扫描器尚未就绪','确认对应工具可用后再主动重试。'],
  SCANNER_NOT_RUN:['部分扫描器没有执行','确认检查配置及适用范围；未执行不等于零发现。'],
  SCANNER_PARTIAL:['扫描器只完成部分范围','优先处理下方覆盖明细中的失败或跳过部分。'],
  SCAN_PARTIAL:['检查只完成部分范围','优先处理下方覆盖明细中的失败或跳过部分。'],
  RULES_NOT_EXECUTED:['部分选定规则未实际执行','检查工具状态与规则适用范围，再主动重试。'],
  RULE_EXECUTION_INCOMPLETE:['部分选定规则未实际执行','检查工具状态与规则适用范围，再主动重试。'],
  RULE_COVERAGE_PARTIAL:['规则仅覆盖部分范围','下方按语言列出已执行规则和文件范围。'],
  LANGUAGE_NOT_COVERED:['部分语言没有执行对应规则','文件可识别不代表规则已经执行。'],
  UNSUPPORTED_LANGUAGE:['部分语言暂无对应规则','查看语言覆盖表，可按需要配置本地规则。'],
  NO_APPLICABLE_RULES:['没有适用于目标的规则','检查语言和规则配置，空结果不能当作检查通过。'],
  VUE_TEMPLATE_NOT_COVERED:['Vue 模板未覆盖','目前只检查支持的脚本块，模板和样式仍需单独检查。'],
  VUE_SCRIPT_BLOCKS_ONLY:['Vue 仅覆盖脚本块','模板、样式及不支持的脚本形式未获得完整检查。'],
  TARGETS_SKIPPED:['部分目标文件被跳过','查看原检查报告中的跳过范围和原因。'],
  FILES_SKIPPED:['部分目标文件被跳过','查看原检查报告中的跳过范围和原因。'],
  EXECUTION_FAILED:['检查执行失败','查看原检查报告中的失败步骤，处理后主动重试。'],
  EXECUTION_INCOMPLETE:['检查执行未完成','已保留的发现有效，但不能判断未完成范围。'],
  EXECUTION_NOT_COMPLETED:['检查执行未完成','已保留的发现有效，但不能判断未完成范围。'],
  EXECUTION_NOT_RUN:['检查尚未执行','按原有入口主动发起检查，本页面不会自动扫描。'],
  EXECUTION_UNKNOWN:['缺少执行完成证据','不能以工具返回成功代替检查完成。'],
  COVERAGE_UNKNOWN:['缺少覆盖范围证据','无法确认哪些规则和文件已经检查。'],
  CHECK_EVIDENCE_LIMITED:['检查证据超出保留上限','这里只展示保留范围，完整范围请查看原报告。'],
  OBSERVATION_LIMIT_REACHED:['观测明细达到上限','这里只展示保留证据，省略部分保持未知。'],
  CURRENT_SOURCE_NOT_VALIDATED:['未重新验证当前源码','这是最近保留结果，源码修改后应主动检查。'],
  LATEST_RETAINED_ONLY:['仅包含保留的历史观测','未观测、已清理或未落盘的问题不在统计中。'],
  NO_EXECUTION_EVIDENCE:['缺少执行完成证据','历史状态不能补记为完成，请查看原检查报告。'],
  NO_CHANGES:['没有待检查变更','本次没有执行新检查，不能解释为已扫描后零发现。'],
  NOT_APPLICABLE:['本次检查不适用于选定目标','确认目标范围和所需检查能力。'],
  CHECK_FAILED:['检查执行失败','查看原报告中的失败步骤，处理后主动重试。'],
  CHECK_CANCELLED:['检查已取消','未完成范围保持未知，可由你主动重新检查。'],
  SCANNER_TIMEOUT:['扫描器执行超时','查看原报告中的超时范围，再决定缩小目标或调整预算。'],
  SCANNER_SKIPPED:['部分扫描器被跳过','确认配置和适用范围，跳过不等于零发现。'],
  RULES_NOT_COVERED:['目标没有获得对应规则检查','查看语言覆盖表，可按需要配置本地规则。'],
  RULES_PARTIAL:['规则仅覆盖部分范围','下方按语言列出实际执行规则和文件数量。'],
  SOURCE_NOT_CURRENT:['检查所用源码已变化或无法确认','在当前源码上主动重新检查，旧结果不证明当前状态。'],
  SCOPED_CHECK:['本次只检查指定范围','范围之外的文件和能力仍未验证。'],
  CAPABILITY_INCOMPLETE:['部分检查能力没有完整执行','查看下方能力状态，优先处理失败或不可用项目。'],
  OBSERVATION_LIMIT:['覆盖明细达到保留上限','这里只展示保留证据，完整范围请查看原检查报告。'],
  PROVIDER_PARTIAL:['分析器声明仅覆盖部分场景','已执行不表示完整语言或调用链覆盖。'],
  OTHER_DIAGNOSTIC:['检查报告包含其他诊断','请查看原报告确认具体原因，此处不推断缺失信息。'],
  NO_RISK_OBSERVATIONS:['没有足够的问题状态证据','未检查或未保留记录都不能证明没有风险。'],
  IDENTITY_UNAVAILABLE:['部分问题缺少稳定身份','不能可靠跨扫描去重，完整待处理总数保持未知。'],
  ITEMS_OMITTED:['问题或状态明细未完整保留','去重结果只覆盖保留身份及状态。'],
  HISTORICAL_ORDER_UNKNOWN:['历史记录的先后关系不明确','历史导入不能证明当前待处理总数。'],
  STATE_WITHOUT_FINDING:['部分处置缺少对应问题记录','无法可靠合并这些状态，完整待处理总数保持未知。'],
  OLDER_REFERENCE_STATE:['收到较早检查的后续状态','旧状态不会覆盖较新的问题记录。'],
  HANDLING_NOT_OBSERVED:['部分用户处置尚未观测','待处理按已观测状态计算；未观测的排除或暂缓不能推断。'],
  STATE_UNKNOWN:['部分问题的最近状态无法确认','完整待处理总数保持未知，请查看原检查结果。'],
  WORKSPACE_UNAVAILABLE:['部分问题缺少项目归属','无法确认跨扫描身份，不跨项目合并问题。'],
  CHECK_INCOMPLETE:['相关检查尚未完整完成','未完成范围可能还有未观测问题，完整待处理总数保持未知。'],
  TASK_NOT_STARTED:['开发核查尚未开始','现有记录尚无已完成检查，等待原开发任务继续。'],
  TASK_REVIEW_PENDING:['开发复核仍在进行','等待原任务完成复核，不能提前显示检查通过。'],
  TASK_REVIEW_INCOMPLETE:['开发复核未完成','下方列出尚未比较的文件数和未完成复核范围。'],
  SNAPSHOT_FILE_LIMIT:['项目文件数量达到检查上限','部分文件未取得完整比较证据，原任务须说明这些范围。'],
  SNAPSHOT_BYTE_LIMIT:['文件内容大小达到检查上限','超出预算的内容未完整比较，原任务须说明未检查范围。'],
  BASELINE_INCOMPLETE:['修改前记录不完整','不能补造修改前证据；缺失范围需在原任务中明确说明。'],
  TASK_SCOPE_UNVERIFIED:['部分变更范围尚未验证','查看未完成比较的文件数量及原任务结果。'],
  REVIEW_CONTEXT_UNREAD:['仍有复核内容未读','继续原任务的复核流程，未读内容不能算已检查。'],
  REVIEW_CAPACITY_REQUIRED:['剩余复核超出当前处理容量','原任务需说明未完成范围，不能把部分完成当作通过。'],
  TASK_STATIC_NOT_EXECUTED:['开发任务的静态检查未执行','查看原任务中的扫描状态和未执行原因。'],
  TASK_STATIC_PARTIAL:['开发任务的静态检查仅覆盖部分范围','人工复核完成不会扩大扫描器实际覆盖，剩余范围仍需说明。'],
  TASK_STATIC_EVIDENCE_UNKNOWN:['开发任务缺少完整静态检查证据','缺失的扫描状态或范围保持未知，不能补记为完整执行。'],
  TASK_CONTEXT_GAPS:['开发核查的关联证据有缺口','结果仅适用于已获得证据的范围。']
 };
 const reason=code=>reasons[code]||['检查记录存在尚未解释的缺口','请查看原报告，诊断编号在下方技术详情中保留。'];
 const badge=(state,text)=>{const b=el('span',text||status(state));b.className='scan-badge';b.setAttribute('data-state',state||'UNKNOWN');return b};
 const details=(title,text)=>{const d=el('details');d.appendChild(el('summary',title));if(text)d.appendChild(el('p',text));return d};
 const table=(headers,rows)=>{const scroll=el('div'),t=el('table'),head=el('thead'),hr=el('tr'),body=el('tbody');scroll.className='scan-table';
  for(const h of headers)hr.appendChild(el('th',h));head.appendChild(hr);t.appendChild(head);
  for(const row of rows){const tr=el('tr');for(const value of row)tr.appendChild(el('td',value));body.appendChild(tr)}t.appendChild(body);scroll.appendChild(t);return scroll};
 const card=(label,value,note,id)=>{const c=el('div');c.className='scan-card';c.appendChild(el('div',label));const v=el('strong',value);v.className='scan-value';v.id=id;c.appendChild(v);c.appendChild(el('small',note));return c};
 const zeroLabel=row=>row.kind==='TASK'?'开发任务核查':row.findings!==0?num(row.findings)+' 次发现':row.check&&row.check.status==='COMPLETED'?'已执行范围内零发现':row.check&&row.check.status==='PARTIAL'?'已执行部分零发现，其他范围未知':'尚不能判断是否零发现';
 const coverageText=check=>{
  if(!check)return '覆盖范围未知';
  const snippets=list(check.languages).filter(r=>!['EXECUTED','NOT_APPLICABLE'].includes(r.status)).map(r=>(languages[r.language]||'其他语言')+'：'+(r.language==='vue'&&r.scope==='SCRIPT_BLOCKS_ONLY'?'仅脚本，模板未覆盖':status(r.status)));
  snippets.push(...list(check.capabilities).filter(r=>!['EXECUTED','COMPLETED','SUCCESS','NOT_APPLICABLE','COVERED'].includes(r.status)).map(r=>(capabilities[r.capability]||'检查能力')+'：'+status(r.status)));
  const counts=check.scope_counts||{},skipped=counts.skipped_files;if(skipped>0)snippets.push(num(skipped)+' 个文件被跳过');if(counts.unverified_files>0)snippets.push(num(counts.unverified_files)+' 个文件尚未完成比较');if(counts.unread_ranges>0)snippets.push(num(counts.unread_ranges)+' 处复核内容未读');if(counts.review_units!=null&&counts.reviewed_units!=null&&counts.review_units>counts.reviewed_units)snippets.push(num(counts.review_units-counts.reviewed_units)+' 个变更单元待复核');if(check.limited)snippets.push('范围明细未完整保留');
  return snippets.length?snippets.slice(0,6).join('；'):check.status==='COMPLETED'?'选定范围已执行；不代表所有漏洞类型均覆盖':'覆盖范围'+status(check.coverage);
 };
 const checkDetails=(check,key)=>{
  const section=el('div');if(!check){section.appendChild(el('p','这条历史记录未保留检查状态和覆盖范围。'));return section}
  const counts=check.scope_counts||{};if(counts.changed_files!=null||counts.review_units!=null||counts.unverified_files!=null)section.appendChild(el('p','变更文件 '+num(counts.changed_files)+' · 未完成比较 '+num(counts.unverified_files)+' · 已复核 / 变更单元 '+num(counts.reviewed_units)+' / '+num(counts.review_units)+' · 未读内容范围 '+num(counts.unread_ranges)+'。缺失的修改前证据不会补记为已检查。'));
  if(counts.target_files!=null||counts.selected_files!=null||counts.skipped_files!=null)section.appendChild(el('p','目标文件 '+num(counts.target_files)+' · 选入检查 '+num(counts.selected_files)+' · 已跳过 '+num(counts.skipped_files)+'。文件数量不等于每行或全部规则均已覆盖。'));
  if(list(check.languages).length)section.appendChild(table(['语言','实际规则覆盖','已执行 / 选定规则','已扫描 / 目标文件','范围限制'],check.languages.map(r=>[languages[r.language]||'其他语言',status(r.status),num(r.executed_rules)+' / '+num(r.selected_rules),num(r.scanned_files)+' / '+num(r.target_files),r.scope==='SCRIPT_BLOCKS_ONLY'?'仅脚本块；模板'+(r.template_status==='NOT_COVERED'?'未覆盖':status(r.template_status)):r.scope==='PLANNED_FILES'?'按本次目标范围':'范围未提供'])));
  if(list(check.capabilities).length)section.appendChild(table(['检查能力','执行状态'],check.capabilities.map(r=>[capabilities[r.capability]||'其他检查能力',status(r.status)])));
  if(list(check.reason_codes).length){const ul=el('ul');for(const code of check.reason_codes){const [title,action]=reason(code);ul.appendChild(el('li',title+'。'+action))}section.appendChild(ul)}
  const raw=details('技术诊断与原始状态','检查 '+(check.status||'UNKNOWN')+' · 执行 '+(check.execution_state||'UNKNOWN')+' · 规则 '+(check.rule_status||'UNKNOWN')+' · 覆盖 '+(check.coverage||'UNKNOWN'));
  raw.setAttribute('data-detail-key',key+':diagnostic');raw.open=opened.has(key+':diagnostic');raw.appendChild(el('p','原因编号：'+(list(check.reason_codes).join('、')||'未提供')));section.appendChild(raw);return section;
 };
 if(!document.getElementById('scanEvidenceStyle')){const style=el('style',`
 #scanOverview,#observationDetails{color:#1b3046;background:#fff;border:1px solid #dce5ef;border-radius:14px;padding:22px;margin:20px 0;font-size:14px;line-height:1.6}
 #scanOverview h2{font-size:20px;color:#173547;margin:0 0 8px}#scanOverview h3{font-size:15px;margin:20px 0 8px}#scanOverview p,#observationDetails p{color:#566b80;line-height:1.7;margin:8px 0}#scanOverview small{font-size:12px;color:#62778c}
 #scanOverview .scan-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap}.scan-badge{display:inline-block;padding:4px 10px;border-radius:20px;font-size:12px;white-space:nowrap;background:#eaf0f6;color:#536b83}
 .scan-badge[data-state=COMPLETED],.scan-badge[data-state=EXECUTED]{background:#e2f3ec;color:#18644d}.scan-badge[data-state=PARTIAL],.scan-badge[data-state=NOT_RUN]{background:#fff0d8;color:#805511}.scan-badge[data-state=FAILED]{background:#fbe6e7;color:#9d3542}
 #scanOverview .scan-cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:18px 0}.scan-card{border:1px solid #dfe7ef;border-radius:10px;padding:15px;background:#f8fafc;min-width:0}.scan-card>div{font-size:13px;color:#426078}.scan-value{display:block;font-size:29px;line-height:1.3;letter-spacing:-.5px;margin:9px 0;color:#183b4c;font-variant-numeric:tabular-nums}.scan-card small{display:block}
 #scanOverview .scan-note{border-left:3px solid #7d9eb8;background:#f2f6fa;padding:11px 14px;border-radius:4px}#scanOverview .scan-warning{border-left-color:#c39343;background:#fff8eb}#scanOverview .scan-empty{padding:16px;border:1px dashed #bdcddb;border-radius:10px;background:#f8fafc}
 #scanOverview .scan-check{border:1px solid #e1e8ef;border-radius:10px;padding:12px 14px;margin:9px 0}#scanOverview summary,#observationDetails summary{cursor:pointer;color:#294e68;line-height:1.7}#scanOverview summary:focus-visible,#observationDetails summary:focus-visible{outline:2px solid #26847c;outline-offset:4px}#scanOverview .scan-check summary{font-weight:600}#scanOverview .scan-check p{font-size:13px}
 #scanOverview .scan-table{overflow:auto;margin:12px 0}#scanOverview table{width:100%;border-collapse:collapse;white-space:normal;min-width:490px;font-size:12px}#scanOverview th,#scanOverview td{background:transparent;color:#405c72;border-bottom:1px solid #e6edf3;padding:10px;text-align:left;vertical-align:top}#scanOverview th{background:#f4f7fa;color:#4a657b}#scanOverview ul{padding-left:22px;color:#5a6b7d}
 #scanOverview .scan-secondary{margin-top:12px;border-top:1px solid #e5ebf2;padding-top:13px}#scanOverview .scan-statuses{display:flex;gap:7px;flex-wrap:wrap;margin:10px 0}#observationDetails>summary{font-weight:600;font-size:16px}#modelEvidence{border:none;box-shadow:none;padding:15px 0;margin:0;background:#fff;color:#1b3046}#modelEvidence h2{color:#294e68}#modelEvidence td{color:#405c72;border-bottom-color:#e6edf3}#modelEvidence details{margin:12px 0}
 @media(max-width:1050px){#scanOverview .scan-cards{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:560px){#scanOverview,#observationDetails{padding:15px}.scan-value{font-size:24px}.scan-card{padding:12px}#scanOverview .scan-head h2{font-size:19px}#scanOverview .scan-cards{gap:8px}}
 `);style.id='scanEvidenceStyle';document.head.appendChild(style)}
 let overview=document.getElementById('scanOverview');if(!overview){overview=el('section');overview.id='scanOverview';const anchor=parent.querySelector('.cards');if(anchor)parent.insertBefore(overview,anchor);else parent.appendChild(overview)}
 const opened=new Set(Array.from(overview.querySelectorAll('details[open]')).map(n=>n.getAttribute('data-detail-key')).filter(Boolean));overview.replaceChildren();overview.setAttribute('aria-label','安全检查总览');
 const metrics=data.product_metrics||{},summary=metrics.check_summary||{},current=metrics.current_risks||{},latest=summary.latest||null;
 const off=data.monitoring&&data.monitoring.mode==='off',scans=metrics.scans==null?null:metrics.scans,checks=summary.observed_checks??scans;
 const scopes={all:'当前采样组的保留记录',project:'当前项目已关联的保留记录',chat:'当前聊天已关联的保留记录',task:'当前手动观察窗口的保留记录',scan:'全部保留扫描结果；下方工具耗时另按扫描入口筛选'};
 const head=el('div');head.className='scan-head';const heading=el('div');heading.appendChild(el('h2','安全检查总览'));heading.appendChild(el('small',scopes[data.scope]||'这份快照中的保留检查记录'));head.appendChild(heading);head.appendChild(badge(off?'NOT_RUN':'OBSERVED',off?'产品观测已关闭':'只读观测'));overview.appendChild(head);
 const note=el('p','数据来自已发生检查的保留记录，'+(data.generated_at?'更新于 '+new Date(data.generated_at*1000).toLocaleString('zh-CN')+'。':'这份报告不会自动刷新。')+' 不重新验证当前源码，也不会自动发起扫描。');note.className='scan-note';overview.appendChild(note);
 if(off){const warning=el('p','产品观测已关闭。历史记录仍可查看；只有你主动选择“基础统计”或“详细调试”后，才会记录后续操作。开启观测不会发起检查。');warning.className='scan-note scan-warning';overview.appendChild(warning)}
 const cards=el('div');cards.className='scan-cards';cards.appendChild(card('最近一次检查',latest?status(latest.status):checks?'状态未知':'尚无结果',latest?(latest.kind==='TASK'?'开发任务核查':'扫描检查')+(latest.observed_at?' · 记录于 '+new Date(latest.observed_at*1000).toLocaleString('zh-CN'):' · 仅适用于该次选定范围'):'没有记录不能视为检查通过','latestCheckStatus'));
 cards.appendChild(card('当前待处理风险 · 去重',num(current.pending),current.pending!=null?'最近保留状态；同一问题重复发现只算一次':'证据不完整，不能确认完整待处理总数','pendingRiskCount'));
 cards.appendChild(card('累计发现次数',num(metrics.cumulative_finding_occurrences??metrics.findings),'按扫描计次；同一问题可在多次扫描中重复出现','cumulativeFindingCount'));
 cards.appendChild(card('已保留检查记录',num(checks),'扫描 '+num(scans)+' 次 · 开发核查 '+num(summary.task_checks)+' 项；不等于全部完成','retainedCheckCount'));overview.appendChild(cards);
 const states=el('div');states.className='scan-statuses';for(const value of ['COMPLETED','PARTIAL','FAILED','NOT_RUN','IN_PROGRESS','UNKNOWN'])if((summary.status_counts||{})[value]>0)states.appendChild(badge(value,status(value)+' '+num(summary.status_counts[value])+' 次'));if(states.childNodes.length)overview.appendChild(states);
 const risk=el('p',current.pending!=null?'待处理风险按最近已观测状态去重；没有再次出现，不会自动记作已解决。'+(current.coverage!=='OBSERVED'?' 部分处置证据未保留，统计仅代表已观测状态。':''):'当前待处理总量未知'+(current.observed_pending!=null?'；已观测未关闭候选 '+num(current.observed_pending)+' 个，仅覆盖保留的问题身份及状态':'')+'。缺失记录可能改变这些状态，未知不能按 0 计算。');risk.className='scan-note';overview.appendChild(risk);
 if(!checks){const empty=el('div');empty.className='scan-empty';empty.appendChild(el('strong',off?'尚未开始记录检查结果':'当前范围还没有检查结果'));empty.appendChild(el('p',off?'先由你主动启用产品观测，再使用原有检查入口。':'可以切换统计范围查看已有记录，或主动运行一次检查。没有保留记录不代表没有风险。'));overview.appendChild(empty)}
 if(latest){const alert=el('div');alert.className='scan-note'+(latest.status==='COMPLETED'?'':' scan-warning');alert.appendChild(el('strong',latest.status==='COMPLETED'?'最近检查已完成于选定范围':latest.status==='IN_PROGRESS'?'最近检查仍在进行':'最近检查尚有缺口'));alert.appendChild(el('p','未覆盖或受限范围：'+coverageText(latest)));
  const codes=[...new Set(list(latest.reason_codes))];for(const code of codes.slice(0,3)){const [title,action]=reason(code);alert.appendChild(el('p',title+'。'+action))}if(latest.status!=='COMPLETED'&&!codes.length)alert.appendChild(el('p','未完成原因未被记录。请查看原检查报告，不能由工具返回成功推断检查完成。'));if(codes.length>3)alert.appendChild(el('small','另有 '+num(codes.length-3)+' 项原因，见下方最近检查明细。'));overview.appendChild(alert)}
 const scanRows=list(metrics.rows),scanById=new Map(scanRows.map(r=>[r.scan,r])),rows=list(metrics.checks).length?metrics.checks.map(c=>({...scanById.get(c.subject),...c,scan:c.subject})):scanRows;
 const recent=[...rows].sort((a,b)=>(b.observed_at||0)-(a.observed_at||0));
 if(rows.length){overview.appendChild(el('h3','最近检查：结果、未完成原因与覆盖范围'));for(const row of recent.slice(0,20)){
  const name=String(row.scan||'检查记录').replace(/^scan-(\d+)$/,'扫描 #$1').replace(/^task-(\d+)$/,'开发核查 #$1');
  const d=details(name+' · '+status(row.check&&row.check.status)+' · '+zeroLabel(row));d.className='scan-check';d.setAttribute('data-detail-key',row.scan||'');d.open=opened.has(row.scan);
  const short=el('small',coverageText(row.check));short.style.display='block';short.style.fontWeight='normal';d.firstElementChild.appendChild(short);
  d.appendChild(el('p',(row.source==='HISTORY'?'历史导入':'执行时观测')+(row.observed_at?' · 记录于 '+new Date(row.observed_at*1000).toLocaleString('zh-CN'):'')+' · '+coverageText(row.check)));d.appendChild(checkDetails(row.check,row.scan));const lines=row.lines||{};
  if(row.kind!=='TASK')d.appendChild(el('p','目标物理行 '+num(lines.target_lines)+' · 确认处理文件的物理行 '+num(lines.confirmed_file_lines)+'。包含空行和注释，不表示逐行或分支覆盖。'));
  if(row.omitted_findings>0)d.appendChild(el('p','另有 '+num(row.omitted_findings)+' 条问题未保留逐条明细，去重和分类统计不完整。'));overview.appendChild(d)}if(rows.length>20)overview.appendChild(el('small','页面显示最近 20 项检查；导出数据保留其余有界明细。'))}
 const more=details('计数口径、已解决状态与历史行数');more.className='scan-secondary';more.setAttribute('data-detail-key','counts');more.open=opened.has('counts');
 more.appendChild(el('p','去重后的已解决 '+num(current.resolved)+' · 已判误报 '+num(current.false_positive)+' · 已排除 '+(current.excluded==null?'未观测':num(current.excluded))+' · 已暂缓 '+(current.deferred==null?'未观测':num(current.deferred))+'。未观测的处置状态不会按 0 计算。'));
 more.appendChild(el('p','宿主新增意见 '+num(metrics.host_proposals)+' 条，单独记录；不自动加入已确认风险。AI 明确确认 '+num(metrics.ai_confirmed)+' 条、可能成立 '+num(metrics.ai_likely)+' 条、误报 '+num(metrics.ai_false_positive)+' 条、未知或待复核 '+num(metrics.ai_unknown)+' 条。以上 AI 结论按保留的问题记录计数，不与去重待处理数相加。'));
 more.appendChild(el('p','原扫描器验证已消除 '+num(metrics.scanner_verified_resolved)+' 条；仅代码复核认为已解决 '+num(metrics.code_reviewed_resolved)+' 条，两种证据分别统计。'));
 more.appendChild(el('p','累计已知目标物理行 '+num(metrics.known_target_lines)+'，确认处理文件的物理行 '+num(metrics.known_confirmed_file_lines)+'；'+num(metrics.scans_without_line_evidence)+' 次扫描没有历史行数证据。重复扫描的行数按次累计，不表示独立代码量。'));
 more.appendChild(el('p','累计发现按扫描结果计数，同一扫描重放不会累加；去重数只覆盖保留的问题身份。未保留逐条发现 '+num(metrics.omitted_findings)+' 条。保留期、观测关闭、进程退出和采集丢失均可能造成缺口。'));
 for(const code of list(current.reason_codes)){const [title,action]=reason(code);more.appendChild(el('p',title+'。'+action))}if(list(current.reason_codes).length)more.appendChild(details('去重统计诊断编号',current.reason_codes.join('、')));overview.appendChild(more);
 let model=document.getElementById('observationDetails');if(!model){model=details('模型请求、输入构成与采集详情');model.id='observationDetails';const footer=parent.querySelector('#updated');if(footer)parent.insertBefore(model,footer);else parent.appendChild(model)}renderModelDetails(data,model);
}
'''
