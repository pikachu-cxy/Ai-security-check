# Distribution staging

`distribution/build/security-check.spec` creates an inspectable PyInstaller one-directory Runtime. `scripts/build_standalone.py` adds notices and version metadata. Semgrep, Gitleaks, Trivy, their rule repositories, and user data are not copied into the Runtime bundle. First Semgrep preparation downloads the separate CPython distribution declared in `security_runtime/python_downloads.json`; its original license inventory remains in the managed directory. URLs and SHA256 values are pinned to the 20260211 upstream build and checked before extraction. No system Python or package environment is modified.

The Homebrew Formula and WinGet manifests are generated **only after all three supported native platform archives have been built and SHA256-verified**. No placeholder URL or checksum is committed. `scripts/make_release_metadata.py` reads each archive's `.verification.json` before writing `dist/release/release-manifest.json` and `SHA256SUMS.txt`; both package-manager generators and `scripts/validate_manager_metadata.py` read that single manifest. The generated Formula belongs in `pikachu-cxy/homebrew-tap`; the WinGet YAML belongs in a later `microsoft/winget-pkgs` submission. Neither external repository is changed by this project.

After these checks and copying the installation guides, `scripts/prepare_release_assets.py` stages only the three native archives, their three `.sha256` files, `SHA256SUMS.txt`, `release-manifest.json`, and one versioned `release-evidence.zip` in a fresh `dist/public-release` directory. The evidence ZIP preserves all remaining release files (including native and specialty JSON receipts and guides) plus the generated Formula and three WinGet YAML files. Original CI artifacts and `dist/release` stay intact. The public checksum list additionally covers the evidence ZIP. Release notes are generated from the same version and manifest, with direct platform download links at the top; an existing draft receives the same notes before publication. Do not reuse a stale public staging directory. See [the review example and expected asset list](../docs/RELEASE_DOWNLOADS_REVIEW.zh-CN.md).

The tag-only release workflow validates each native archive before creating a draft GitHub Release and publishes the draft only after all assets upload. Uninstalling the Runtime does not remove the user data directory, managed scanners, scan history, or Trivy DB.

Runtime Core remains proprietary under `LICENSE` and `EULA.md`; the public
Plugin API and `ai-security-core` rules remain Apache-2.0. Every bundle includes
`LICENSING.md`, `EULA.md`, the original Apache license, dependency notices and
source locations. The custom Homebrew tap uses `license :cannot_represent`
for the proprietary product; WinGet uses `License: Proprietary`. These are
not submissions to homebrew/core and do not relicense Core or third-party code.

## Local native verification

Install the development extras `.[test,build-standalone]`, then run:

```text
python scripts/build_standalone.py
python scripts/package_artifact.py --platform windows-x64
python scripts/verify_artifact.py --full dist/release/ai-security-runtime-v0.3.1-windows-x64.zip
```

Use the actual host platform for macOS or Linux. The verifier extracts to a fresh
directory, removes Python and scanners from PATH, uses a separate user data
directory, prepares all three scanners and the Trivy DB, scans a Python source
file plus a dependency manifest, and opens a real MCP SDK stdio session. It
records the archive SHA256 and actual native platform. This is separate from
the offline source compliance workflow.

## First external publication

1. Review the three native CI verification records and tag the approved feature
   commit with the version from `security_runtime/_version.py`. The tag workflow
   publishes GitHub assets only after every gate passes.
2. Copy the generated Formula into the user-created `pikachu-cxy/homebrew-tap`
   repository. Run `brew install`, `brew test`, `brew upgrade` with a later
   verified release, and `brew uninstall` on each supported platform.
3. Run `winget validate distribution/winget` on Windows. Enable local manifests
   if needed, then test `winget install --manifest distribution/winget`, version,
   scan and uninstall. Upgrade requires a second real published version. Submit
   the reviewed YAML to `microsoft/winget-pkgs` manually.

`scripts/validate_manager_metadata.py` checks the vendored official WinGet JSON
schemas and matches both package managers to actual archive checksums. This
static validation does not claim a package-manager installation or upgrade.
Until GitHub assets and external package listings exist, generated URL metadata
is release staging data and the README keeps installation commands marked
unavailable. No PyPI publication or external repository is performed here.
