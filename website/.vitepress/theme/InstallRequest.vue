<script setup>
import { computed, ref, watch } from 'vue'

const props = defineProps({ editor: { type: String, default: '' } })
const selectedEditor = ref('codex')
const editors = {
  codex: {
    name: 'Codex',
    target: '接入本地 Codex',
    page: 'codex',
    steps: 'Windows 按本页 PowerShell 命令自动安装并选择 codex；macOS 按本页命令自动安装并选择 codex，先说明验证范围及已有 Codex 连接可能更新。配置用户级 MCP、Skill 和 Hook，并自动准备检查组件。',
    note: '粘贴到本机 Codex 聊天。Windows 自动下载校验完整包，Mac 自动准备专用运行环境；已有 Codex 连接可能更新为所选版本。'
  },
  cursor: {
    name: 'Cursor',
    target: '接入本地 Cursor',
    page: 'cursor',
    steps: '阅读 Cursor 接入指南中的支持说明。Windows 按本页 PowerShell 命令自动安装并选择 cursor；macOS 按本页命令自动安装并选择 cursor，先说明验证范围及已有 Cursor 连接可能更新。配置用户级 MCP、配套 Skill 和 Hook，并自动准备检查组件；常规工具确认仍遵循 Cursor 的运行模式与团队策略。',
    note: '粘贴到本机 Cursor 的 Agent 聊天。Windows 自动下载校验完整包，Mac 自动准备专用运行环境；已有 Cursor 连接可能更新为所选版本。'
  },
  workbuddy: {
    name: 'WorkBuddy',
    target: '接入本地 WorkBuddy',
    page: 'workbuddy',
    steps: '按 WorkBuddy 指南执行官方安装命令。完全退出并重启 WorkBuddy，再审核 MCP 服务信任。',
    note: '粘贴到本机 WorkBuddy 聊天。安装后按提示重启并确认实际连接。'
  },
}
const editor = computed(() => editors[props.editor || selectedEditor.value] || editors.codex)
const copied = ref(false)
const copyFailed = ref(false)
const request = computed(() => `请按 https://pikachu-cxy.github.io/Ai-security-check/install/agent.md 的官方指南，在本机安装 AI Security Runtime 并接入 ${editor.value.name}，保留现有配置，验证版本、构建与连接状态，并说明需要我完成的重启或信任步骤。`)

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
      <strong>推荐：让 AI 帮你安装</strong>
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
      <textarea aria-label="安装请求正文" readonly :value="request" rows="4" @focus="$event.target.select()"></textarea>
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
