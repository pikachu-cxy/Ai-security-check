<script setup>
import { withBase } from 'vitepress'
import InstallRequest from './InstallRequest.vue'

const steps = [
  { number: '01', title: '检查本次改动', text: '从编辑前的真实工作区开始，记录新增、修改与删除，保留已有改动的边界。' },
  { number: '02', title: '解释风险依据', text: '结合静态检查与宿主 Agent 的有限上下文复核，说明问题、防护、影响和未知项。' },
  { number: '03', title: '由你决定处理', text: '选择具体问题后批准修复；也可以稍后处理，或根据证据排除并保留记录。' },
  { number: '04', title: '沿原问题复查', text: '将修复与原问题关联，区分已解决、仍存在和证据不足，不用新任务覆盖旧结论。' }
]
</script>

<template>
  <main id="main-content" class="product-home">
    <section class="hero-section" aria-labelledby="product-title">
      <div class="hero-copy">
        <p class="eyebrow"><span class="status-dot" aria-hidden="true"></span>LOCAL SECURITY RUNTIME / DEVELOPER ALPHA</p>
        <h1 id="product-title">让 AI 写代码，<br>也让风险<span>有据可查。</span></h1>
        <p class="hero-description">在 Codex、Cursor 中照常提出开发需求，同时查看本次改动里的安全问题。看懂风险、决定如何处理，批准修复后再沿原问题复查。</p>
        <div class="hero-actions">
          <a class="primary-action" :href="withBase('/guide/quickstart.html')">开始使用 <span aria-hidden="true">↗</span></a>
          <a class="secondary-action" :href="withBase('/guide/overview.html')">了解工作方式 <span aria-hidden="true">→</span></a>
        </div>
        <p class="hero-note">Windows / macOS · <a :href="withBase('/guide/editors/codex.html')">Codex 安装</a> · <a :href="withBase('/guide/editors/cursor.html')">Cursor 安装</a></p>
      </div>
      <div class="review-example" aria-label="示意：一次开发任务的风险说明和用户选择">
        <div class="example-heading"><span class="example-dots" aria-hidden="true">● ● ●</span><span>一次开发任务 / 示例</span><span class="example-tag">REVIEW</span></div>
        <div class="example-body">
          <p class="example-user">“给项目增加一个文件下载接口。”</p>
          <div class="example-event"><span aria-hidden="true">✓</span> 已记录编辑前版本</div>
          <div class="example-event"><span aria-hidden="true">✓</span> 已检查改动及必要关联代码</div>
          <div class="example-finding">
            <div class="finding-label">需要你关注</div>
            <h2>下载目标缺少目录边界校验</h2>
            <p>若文件名由外部输入控制，路径解析后可能越出允许的下载目录。还需结合接口权限与部署条件判断影响。</p>
            <div class="example-evidence"><code>输入来源 → 路径校验 → 文件读取</code></div>
          </div>
          <div class="example-choices"><span>修复此问题</span><span>稍后处理</span><span>补充排除依据</span></div>
          <p class="example-caption">示意内容；实际结果取决于代码、规则与已检查范围。</p>
        </div>
      </div>
    </section>

    <InstallRequest />

    <section class="workflow-section" aria-labelledby="workflow-title">
      <div class="section-heading"><p class="eyebrow">ONE CONNECTED WORKFLOW</p><h2 id="workflow-title">从发现，到处理，再到复查。</h2><p>把检查结果留在正在进行的开发任务中。</p></div>
      <ol class="workflow-grid">
        <li v-for="step in steps" :key="step.number"><span class="step-number">{{ step.number }}</span><h3>{{ step.title }}</h3><p>{{ step.text }}</p></li>
      </ol>
    </section>

    <section class="architecture-section" aria-labelledby="architecture-title">
      <div class="architecture-copy"><p class="eyebrow">CLEAR RESPONSIBILITIES</p><h2 id="architecture-title">Agent 理解代码，<br>Runtime 管理证据。</h2><p>扫描器提供实际执行结果；宿主 Agent 读取必要上下文、解释和修复；Runtime 核对范围、版本、授权及原问题记录。</p><a class="text-link" :href="withBase('/guide/workflow.html')">查看完整流程 <span aria-hidden="true">→</span></a></div>
      <dl class="responsibilities">
        <div><dt>你的编程助手</dt><dd>理解需求、分析上下文、执行已批准的修改</dd></div>
        <div><dt>本地 Runtime</dt><dd>任务基线、扫描编排、证据、状态与复查</dd></div>
        <div><dt>检测能力</dt><dd>代码规则、有限数据流、密钥和依赖检查</dd></div>
      </dl>
    </section>

    <section class="start-section" aria-labelledby="start-title">
      <div><p class="eyebrow">START WITH YOUR WORKFLOW</p><h2 id="start-title">接入你正在使用的工作方式。</h2><p>默认完整接入；需要时也可手动配置仅 MCP。</p></div>
      <div class="start-links">
        <a :href="withBase('/guide/quickstart.html')"><strong>完整接入</strong><span>MCP + Skill + Hook</span><span aria-hidden="true">↗</span></a>
        <a :href="withBase('/guide/mcp.html')"><strong>仅 MCP</strong><span>手动配置，按需调用工具</span><span aria-hidden="true">↗</span></a>
      </div>
    </section>

    <section class="scope-section" aria-labelledby="scope-title"><h2 id="scope-title">了解这次检查覆盖了什么。</h2><p>检查结果会说明发现的问题、实际覆盖范围和未完成项。当前产品处于 Developer Alpha 阶段，各系统与编辑器的验证记录见支持范围；零发现不代表整个项目安全。</p><div><a :href="withBase('/reference/support.html')">支持范围</a><a :href="withBase('/reference/privacy.html')">数据与隐私</a><a :href="withBase('/reference/changelog.html')">版本与进展</a></div></section>
  </main>
</template>
