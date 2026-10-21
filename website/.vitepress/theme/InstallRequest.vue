<script setup>
import { computed, ref, watch } from 'vue'

const props = defineProps({ editor: { type: String, default: '' } })
const selectedEditor = ref('codex')
const editors = {
  codex: {
    name: 'Codex',
    target: '接入本地 Codex',
    page: 'codex',
    steps: 'Windows 使用完整包的 install codex 入口；macOS 按本页命令自动安装并选择 codex，先说明验证范围及已有 Codex 连接可能更新。配置用户级 MCP、Skill 和 Hook，并自动准备检查组件。',
    note: '粘贴到本机 Codex 聊天。Windows 使用完整包，Mac 自动准备专用运行环境；已有 Codex 连接可能更新为所选版本。'
  },
  cursor: {
    name: 'Cursor',
    target: '接入本地 Cursor',
    page: 'cursor',
    steps: '阅读 Cursor 接入指南中的支持说明。Windows 使用完整包的 install cursor 入口；macOS 按本页命令自动安装并选择 cursor，先说明验证范围及已有 Cursor 连接可能更新。配置用户级 MCP、配套 Skill 和 Hook，并自动准备检查组件；常规工具确认仍遵循 Cursor 的运行模式与团队策略。',
    note: '粘贴到本机 Cursor 的 Agent 聊天。Windows 使用完整包，Mac 自动准备专用运行环境；已有 Cursor 连接可能更新为所选版本。'
  },
  workbuddy: {
    name: 'WorkBuddy',
    target: '为当前项目配置 WorkBuddy 的 MCP 连接',
    page: 'workbuddy',
    steps: '先确认当前本地 Git 项目的绝对路径，将完整包放在长期保留的位置。准备检查组件，再使用 setup workbuddy --path "<实际项目绝对路径>" 配置该项目的 .workbuddy/mcp.json，合并并保留已有服务。这是项目级 MCP 接入，不包含自动编辑检查；桌面实际调用仍需验证。',
    note: '粘贴到可在本机执行命令的 WorkBuddy 聊天。请求会按项目配置 MCP，连接后需主动提出检查需求。'
  },
  other: {
    name: '其他 MCP 客户端',
    target: '接入我实际使用的 MCP 客户端',
    page: 'other',
    steps: '先确认客户端名称、当前本地 Git 项目绝对路径，以及该客户端当前支持的本地 stdio MCP 格式；缺少信息时先问我。将完整包放在长期保留的位置，准备检查组件，使用 mcp config --path "<实际项目绝对路径>" 生成所需 JSON 或 TOML 服务条目，合并到该客户端对应的配置中，保留绝对程序路径、工作区绑定和其他服务。无法确认支持时说明具体限制，不猜测专用安装命令或配置位置。本路径只配置 MCP，不承诺自动编辑检查。',
    note: '适用于支持本地 stdio MCP、可在本机执行命令的助手；粘贴时说明客户端名称和项目路径。只支持聊天的客户端请按手动步骤操作。'
  }
}
const editor = computed(() => editors[props.editor || selectedEditor.value] || editors.codex)
const installSource = computed(() => ['codex', 'cursor'].includes(editor.value.page)
  ? '自动识别系统与芯片。Windows 选择官方最新发行的完整包，下载并核验官方 SHA256 和包内完整性后再运行。macOS 按当前编辑器页面使用发行 macos-trial-v0.3.9.1 的安装入口 https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh，选择对应编辑器并遵循脚本的固定下载校验，不要求我预装 Python、Git 或 Homebrew。该试用尚未完成真实 M 系列 Mac 桌面验收，不宣称 Apple 签名或公证已验证。'
  : '自动识别系统与芯片，选择官方最新发行的完整包，下载并核验官方 SHA256 和包内完整性后再运行。')

const copied = ref(false)
const copyFailed = ref(false)
const request = computed(() => `请根据 https://pikachu-cxy.github.io/Ai-security-check/guide/editors/${editor.value.page}.html 的官方安装说明，在当前电脑安装 AI Security Runtime，并${editor.value.target}。
${installSource.value}备份并保留现有配置、其他 MCP 服务及用户修改。
${editor.value.steps}
核对组件及漏洞数据状态，仍在后台准备时明确说明；不要自行用源码开发安装替代官方发行或官方试用入口，不关闭系统安全保护或 TLS 校验。遇到 macOS 粘贴保护提示时，让我核对命令与来源并自行决定；检测到恶意软件时停止。遇到签名、证书、权限或配置冲突时，保留具体诊断并说明下一步，不擅自删除文件或绕过安全检查。需要权限时遵循当前客户端的正常审批流程。
安装期间保持当前聊天，完成后核对版本、build_id、组件状态与漏洞库有效期，分别说明安装结果和仍待验证的步骤，并提示我重启${editor.value.name === '其他 MCP 客户端' ? '实际使用的客户端' : editor.value.name}生效。重启后通过实际工具调用确认连接和项目路径；无法确认的部分明确列出。不扫描或修改我的业务项目。`)

watch(editor, () => {
  copied.value = false
  copyFailed.value = false
})

async function copyRequest() {
  copied.value = false
  const text = request.value
  try {
    await navigator.clipboard.writeText(text)
    if (request.value === text) {
      copied.value = true
      copyFailed.value = false
    }
  } catch {
    if (request.value === text) copyFailed.value = true
  }
}
</script>

<template>
  <section class="install-request" aria-label="让 AI 帮你安装和接入">
    <div class="install-request-heading">
      <strong>把安装请求发给助手</strong>
      <button type="button" @click="copyRequest">{{ copied ? '已复制安装请求' : '复制安装请求' }}</button>
    </div>
    <label v-if="!props.editor" class="editor-select">
      <span>要接入的编辑器</span>
      <select v-model="selectedEditor">
        <option v-for="(option, key) in editors" :key="key" :value="key">{{ option.name }}</option>
      </select>
    </label>
    <p>{{ editor.note }} 这是发给聊天的请求，请勿粘贴到终端。联网或写入配置时，按宿主提示确认权限。</p>
    <p role="status" aria-live="polite">{{ copied ? `已复制 ${editor.name} 安装请求，请粘贴到对应助手的聊天。` : copyFailed ? '浏览器未允许复制，请展开下方请求并手动复制。' : '安装完成后重启对应客户端，再检查连接、版本、组件和项目路径。' }}</p>
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
button:focus-visible, select:focus-visible, textarea:focus-visible, summary:focus-visible { outline: 2px solid var(--vp-c-brand-1); outline-offset: 4px; }
.editor-select { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; margin-top: 16px; font-size: 14px; }
select { padding: 8px 12px; border: 1px solid var(--vp-c-divider); border-radius: 6px; background: var(--vp-c-bg); color: var(--vp-c-text-1); font: inherit; }
p { font-size: 14px; line-height: 1.8; color: var(--vp-c-text-2); margin: 12px 0; }
summary { cursor: pointer; font-size: 14px; }
textarea { display: block; width: 100%; margin-top: 12px; padding: 12px; resize: vertical; background: var(--vp-c-bg); color: var(--vp-c-text-1); border: 1px solid var(--vp-c-divider); border-radius: 4px; font: inherit; font-size: 13px; line-height: 1.8; }
</style>
