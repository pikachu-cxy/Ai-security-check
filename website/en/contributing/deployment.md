# Maintain and deploy the documentation

The user-facing site is in `website/` and uses VitePress. Engineering records remain in `docs/`; the two have different audiences.

## Local development

Documentation development needs Node.js; bundled Runtime users do not. CI uses Node.js 24.

```sh
cd website
npm ci
npm run docs:dev
```

## Build and preview

```sh
npm run docs:build
npm run docs:preview
```

The default base is `/Ai-security-check/`. The build checks internal page links. Also inspect desktop and narrow-screen layout, navigation, search, language switching, and installation commands.

## Languages

Chinese remains at the site root, and English lives under `website/en/`. The root README is English; `README.zh-CN.md` retains the full Chinese version. Shared site settings and locale-specific navigation are in `.vitepress/config.mts`.

When adding a user-facing page, create the matching path for both locales and update their sidebars. Keep installation commands, release status, privacy boundaries, and license scope aligned. Engineering references can remain in their original language if the link labels say so. The English guides summarize the same supported workflows; they do not extend product capabilities.

## GitHub Pages

The repository's `.github/workflows/docs.yml` builds documentation changes on `feature/runtime-mvp` and checks pull requests without deploying them. The default-branch workflow copies the managed macOS installer into the site. Deployment waits for all documented native and managed-installation assets to be public.

In GitHub Settings → Pages, use GitHub Actions as the source. Treat the public site as updated only after the deployment job succeeds; a local build or skipped deployment is not publication. Public URL: [English documentation](https://pikachu-cxy.github.io/Ai-security-check/en/).

The workflow uses Pages-specific permissions and does not require committing a personal access token. A custom domain requires separate DNS and Pages setup, with `DOCS_BASE=/` as appropriate.

## Content maintenance

Keep source commits, candidate builds, published packages, and real desktop acceptance distinct. Use actual release assets and matching checksums. Do not publish private paths, secrets, raw diagnostics, or unsupported claims about performance, users, or security coverage.

Audit shared footers, copyable installation requests, public redirects, daily workflows, and FAQs in both languages rather than updating downloads alone. Keep product and managed-macOS identifiers separate: currently 0.3.10 / `macos-trial-v0.3.10`. Describe current behavior in user guides and retain old capabilities and acceptance records in the changelog. Source commits, manifests, and successful release runs must identify the same delivery; cancelled or failed candidates are not its evidence.

The deploy workflow copies `distribution/macos/install.sh` into `install/macos.sh`, emits its SHA256, and checks the documented native and managed macOS assets before deployment. Update both release references together with download pages; do not replace a published artifact under an existing version.
