import { defineConfig } from 'vitepress'

const repository = 'https://github.com/pikachu-cxy/Ai-security-check'
const base = process.env.DOCS_BASE || '/Ai-security-check/'

export default defineConfig({
  lang: 'zh-CN',
  title: 'AI Security Runtime',
  description: '为 AI 编程接上有证据、可追溯的安全核查。检查改动、解释风险、授权修复、沿原问题复查。',
  base,
  cleanUrls: false,
  lastUpdated: true,
  locales: {
    root: { label: '简体中文', lang: 'zh-CN' },
    en: {
      label: 'English',
      lang: 'en',
      description: 'Security checks, evidence, and fix verification for AI coding workflows.',
      head: [
        ['meta', { property: 'og:title', content: 'AI Security Runtime · Security checks for AI coding' }],
        ['meta', { property: 'og:description', content: 'Review changes, understand risks, approve fixes, and verify the original finding.' }]
      ],
      themeConfig: {
        nav: [
          { text: 'Overview', link: '/en/guide/overview' },
          { text: 'Get started', link: '/en/guide/quickstart' },
          { text: 'Language coverage', link: '/en/reference/support#languages' },
          { text: 'Downloads', link: '/en/downloads' },
          { text: 'Changelog', link: '/en/reference/changelog' }
        ],
        sidebar: [
          { text: 'Getting started', collapsed: false, items: [
            { text: 'Quick start', link: '/en/guide/quickstart' },
            { text: 'Verify installation', link: '/en/guide/verify' },
            { text: 'Your first demo', link: '/en/guide/demo' },
            { text: 'Downloads', link: '/en/downloads' }
          ] },
          { text: 'Connect your editor', collapsed: false, items: [
            { text: 'Codex', link: '/en/guide/editors/codex' },
            { text: 'Cursor', link: '/en/guide/editors/cursor' },
            { text: 'WorkBuddy', link: '/en/guide/editors/workbuddy' },
            { text: 'Other MCP clients', link: '/en/guide/editors/other' }
          ] },
          { text: 'Using the runtime', collapsed: false, items: [
            { text: 'Daily workflow', link: '/en/guide/workflow' },
            { text: 'Usage monitoring and reports', link: '/en/guide/context-cost' },
            { text: 'Handle findings', link: '/en/guide/risk-handling' },
            { text: 'Practice checklist', link: '/en/guide/playground' },
            { text: 'Troubleshooting', link: '/en/reference/faq' }
          ] },
          { text: 'Advanced setup', collapsed: true, items: [
            { text: 'Preparation and upgrades', link: '/en/guide/installation' },
            { text: 'Manual MCP setup', link: '/en/guide/mcp' }
          ] },
          { text: 'Product and support', collapsed: true, items: [
            { text: 'Product overview', link: '/en/guide/overview' },
            { text: 'Platforms and coverage', link: '/en/reference/support' },
            { text: 'Data and privacy', link: '/en/reference/privacy' },
            { text: 'Changelog', link: '/en/reference/changelog' },
            { text: 'Licensing', link: '/en/reference/legal' },
            { text: 'Maintain the documentation', link: '/en/contributing/deployment' }
          ] }
        ],
        langMenuLabel: 'Language',
        sidebarMenuLabel: 'Menu',
        returnToTopLabel: 'Back to top',
        skipToContentLabel: 'Skip to content',
        darkModeSwitchLabel: 'Appearance',
        lightModeSwitchTitle: 'Switch to light theme',
        darkModeSwitchTitle: 'Switch to dark theme',
        outline: { label: 'On this page', level: [2, 3] },
        docFooter: { prev: 'Previous page', next: 'Next page' },
        lastUpdated: { text: 'Last updated' },
        editLink: { pattern: `${repository}/edit/feature/runtime-mvp/website/:path`, text: 'Edit this page on GitHub' },
        footer: {
          message: '0.3.11 · Official release · Check the installed build and actual review coverage.',
          copyright: 'Runtime Core and third-party components have separate licenses.'
        }
      }
    }
  },
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}logo.svg` }],
    ['meta', { name: 'theme-color', content: '#087f5b' }],
    ['meta', { property: 'og:title', content: 'AI Security Runtime · 把安全核查接入 AI 编程' }],
    ['meta', { property: 'og:description', content: '从本次改动到原问题复查，让风险依据、用户选择和处理记录连在一起。' }]
  ],
  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'AI Security Runtime',
    nav: [
      { text: '了解产品', link: '/guide/overview' },
      { text: '使用文档', link: '/guide/quickstart' },
      { text: '语言覆盖', link: '/reference/support#语言覆盖' },
      { text: '获取安装包', link: '/downloads' },
      { text: '版本与进展', link: '/reference/changelog' }
    ],
    sidebar: [
      { text: '开始使用', collapsed: false, items: [
        { text: '快速开始', link: '/guide/quickstart' },
        { text: '安装成功了吗？', link: '/guide/verify' },
        { text: '第一个使用 Demo', link: '/guide/demo' },
        { text: '获取安装包', link: '/downloads' }
      ] },
      { text: '接入你的编辑器', collapsed: false, items: [
        { text: 'Codex', link: '/guide/editors/codex' },
        { text: 'Cursor', link: '/guide/editors/cursor' },
        { text: 'WorkBuddy', link: '/guide/editors/workbuddy' },
        { text: '其他 MCP 客户端', link: '/guide/editors/other' }
      ] },
      { text: '使用与练习', collapsed: false, items: [
        { text: '日常怎么用', link: '/guide/workflow' },
        { text: '一键监控与导出报告', link: '/guide/context-cost' },
        { text: '理解与处理风险', link: '/guide/risk-handling' },
        { text: '动手测试用例', link: '/guide/playground' },
        { text: '常见问题与故障排查', link: '/reference/faq' }
      ] },
      { text: '高级配置', collapsed: true, items: [
        { text: '安装参数、准备与升级', link: '/guide/installation' },
        { text: '手动配置 MCP', link: '/guide/mcp' }
      ] },
      { text: '产品与支持', collapsed: true, items: [
        { text: '产品介绍', link: '/guide/overview' },
        { text: '平台与检测范围', link: '/reference/support' },
        { text: '数据、网络与隐私', link: '/reference/privacy' },
        { text: '版本与进展', link: '/reference/changelog' },
        { text: '许可与支持', link: '/reference/legal' },
        { text: '维护文档站', link: '/contributing/deployment' }
      ] }
    ],
    socialLinks: [{ icon: 'github', link: repository }],
    search: { provider: 'local', options: { locales: { root: { translations: {
      button: { buttonText: '搜索文档', buttonAriaLabel: '搜索文档' },
      modal: { noResultsText: '没有找到相关内容', resetButtonTitle: '清除搜索',
        footer: { selectText: '选择', navigateText: '切换', closeText: '关闭' } }
    } } } } },
    outline: { label: '本页内容', level: [2, 3] },
    docFooter: { prev: '上一页', next: '下一页' },
    lastUpdated: { text: '最近更新' },
    editLink: { pattern: `${repository}/edit/feature/runtime-mvp/website/:path`, text: '在 GitHub 上改进此页' },
    footer: {
      message: '0.3.11 正式版 · 实际能力以所用构建与检查记录为准。',
      copyright: 'Runtime Core 许可与第三方组件许可分别适用。'
    }
  }
})
