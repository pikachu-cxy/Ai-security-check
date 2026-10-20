<script setup>
import { withBase } from 'vitepress'

const editors = [
  { name: 'Codex', label: '完整接入', path: 'codex', description: '一条命令安装，接着在项目聊天中使用。' },
  { name: 'Cursor', label: 'Windows 测试版', path: 'cursor', description: '下载完整包，再验证本地编辑检查。' },
  { name: 'WorkBuddy', label: '项目级 MCP', path: 'workbuddy', description: '为当前项目配置服务，主动发起检查。' },
  { name: '其他 MCP 客户端', label: '手动配置', path: 'other', description: '查看通用接入条件与各工具支持范围。' }
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
