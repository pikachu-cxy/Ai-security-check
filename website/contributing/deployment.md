# 文档开发与部署

文档站源码在仓库 `website/`，使用 VitePress。面向用户的产品站与仓库 `docs/` 工程记录分工：前者帮助理解、安装和使用，后者保留架构、契约与验收依据。

## 本地开发

文档开发需要 Node.js；这不是完整包最终用户的安装要求。CI 使用 Node.js 24。

```sh
cd website
npm ci
npm run docs:dev
```

## 构建与预览

```sh
npm run docs:build
npm run docs:preview
```

默认以 `/Ai-security-check/` 为站点 base，访问终端显示地址下的这一前缀。构建包含站内链接检查；正式发布前需检查桌面与窄屏布局、导航、搜索和安装命令。

## GitHub Pages

仓库已配套 `.github/workflows/docs.yml`：

1. 将文档与工作流改动提交至默认分支 `feature/runtime-mvp`。
2. 在仓库 **Settings → Pages → Build and deployment** 将 Source 设为 **GitHub Actions**。
3. 文档工作流先运行 `npm ci` 和站点构建；默认分支的非 PR 构建才进入 Pages 部署，PR 只构建。
4. 在 Actions 确认部署成功后，再把站点视为已上线。

默认项目站已于 2026-10-19 首次部署成功：[pikachu-cxy.github.io/Ai-security-check/](https://pikachu-cxy.github.io/Ai-security-check/)。后续工作树编辑仍需推送并确认部署成功，不能将本地预览视为公开更新。自定义域名需要另行配置 DNS、Pages 域名与 `DOCS_BASE=/`。

工作流仅使用 Pages 部署所需的最小权限，不需要在仓库保存个人访问令牌。不要用不受信任的 PR 构建直接部署生产站。

平台细节可查阅 [VitePress 部署指南](https://vitepress.dev/guide/deploy#github-pages) 与 [GitHub Pages 自定义工作流](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)。

## 内容维护

中文页面保留在站点根目录，英文页面位于 `website/en/`；通过 `.vitepress/config.mts` 的语言菜单切换。GitHub 主 `README.md` 使用英文，`README.zh-CN.md` 保留完整中文说明。新增用户页面时，两种语言使用对应路径并分别更新导航；安装命令、发行状态、支持边界、隐私和许可范围需同步维护。工程记录可以保留原语言，链接中应标明。

- 版本能力以真实源码、构建身份与验证证据为准，不把路线图写成已交付功能。
- 新版候选包、CI 产物、正式 Release 和手工验收分别记录。
- 公开 Release 上传后，更新下载页的真实链接与对应校验文件。
- 不在文档中放入私有路径、密钥、原始诊断或不真实的性能与用户数据。
