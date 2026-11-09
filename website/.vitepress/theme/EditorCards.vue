<script setup>
import { withBase } from 'vitepress'

const editors = [
  { name: 'Codex', label: 'Windows / macOS', path: 'codex', description: '选择系统安装，重启验证后完成第一个小任务。' },
  { name: 'Cursor', label: 'Windows / macOS', path: 'cursor', description: '按系统接入 Cursor，在 Agent 聊天中查看改动检查。' },
]
</script>

<template>
  <div class="editor-cards" aria-label="选择编辑器">
    <a v-for="editor in editors" :key="editor.path" :href="withBase(`/guide/editors/${editor.path}.html`)">
      <span class="editor-card-label">{{ editor.label }}</span>
      <strong>{{ editor.name }} <span aria-hidden="true">↗</span></strong>
      <span class="editor-card-description">{{ editor.description }}</span>
    </a>
  </div>
</template>
