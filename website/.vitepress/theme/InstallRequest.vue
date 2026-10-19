<script setup>
import { ref } from 'vue'

const copied = ref(false)
const copyFailed = ref(false)
const request = `请根据 https://pikachu-cxy.github.io/Ai-security-check/ 的官方安装说明，在当前电脑安装 AI Security Runtime，并接入本地 Codex。
自动识别系统与芯片，选择官方最新发行的完整包，下载并核验官方 SHA256 和包内完整性后再运行。备份并保留现有配置、其他 MCP 服务及用户修改，使用产品安装入口配置 MCP、Skill 和 Hook，等待组件及漏洞数据就绪。
不要用源码开发安装替代发行包，不关闭系统安全保护或 TLS 校验。遇到签名、证书、权限或配置冲突时，保留具体诊断并说明下一步，不擅自删除文件或绕过安全检查。需要权限时遵循 Codex 的正常审批流程。
安装期间保持当前聊天，完成后核对版本、build_id、组件状态与漏洞库有效期，分别说明安装结果和仍待验证的步骤，并提示我重启 Codex 生效。不扫描或修改我的业务项目。`

async function copyRequest() {
  copied.value = false
  try {
    await navigator.clipboard.writeText(request)
    copied.value = true
    copyFailed.value = false
  } catch {
    copyFailed.value = true
  }
}
</script>

<template>
  <section class="install-request" aria-label="让 Codex 帮你安装">
    <div class="install-request-heading">
      <strong>让 Codex 帮你安装</strong>
      <button type="button" @click="copyRequest">{{ copied ? '已复制安装请求' : '复制安装请求' }}</button>
    </div>
    <p>复制后粘贴到本地 Codex 聊天，由它下载、核验和安装。联网或写入用户目录时，可能需要你确认权限。</p>
    <p role="status" aria-live="polite">{{ copied ? '已复制，请粘贴到本地 Codex。' : copyFailed ? '浏览器未允许复制，请展开下方请求并手动复制。' : '安装完成后再重启 Codex，让新配置生效。' }}</p>
    <details :open="copyFailed">
      <summary>查看安装请求</summary>
      <textarea aria-label="安装请求正文" readonly :value="request" rows="10" @focus="$event.target.select()"></textarea>
    </details>
  </section>
</template>

<style scoped>
.install-request { padding: 22px; margin: 24px 0; border: 1px solid var(--vp-c-divider); border-radius: 8px; background: var(--vp-c-bg-soft); }
.install-request-heading { display: flex; flex-wrap: wrap; gap: 16px; justify-content: space-between; align-items: center; }
button { border-radius: 6px; background: var(--vp-c-brand-3); color: white; padding: 10px 16px; font-weight: 600; cursor: pointer; }
button:focus-visible, textarea:focus-visible, summary:focus-visible { outline: 2px solid var(--vp-c-brand-1); outline-offset: 4px; }
p { font-size: 14px; line-height: 1.8; color: var(--vp-c-text-2); margin: 12px 0; }
summary { cursor: pointer; font-size: 14px; }
textarea { display: block; width: 100%; margin-top: 12px; padding: 12px; resize: vertical; background: var(--vp-c-bg); color: var(--vp-c-text-1); border: 1px solid var(--vp-c-divider); border-radius: 4px; font: inherit; font-size: 13px; line-height: 1.8; }
</style>
