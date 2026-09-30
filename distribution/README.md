# Distribution staging

`distribution/build/security-check.spec` creates an inspectable PyInstaller one-directory Runtime. `scripts/build_standalone.py` adds notices and version metadata. Semgrep, Gitleaks, Trivy, their rule repositories, and user data are not copied into the Runtime bundle. First Semgrep preparation downloads the separate CPython distribution declared in `security_runtime/python_downloads.json`; its original license inventory remains in the managed directory. URLs and SHA256 values are pinned to the 20260211 upstream build and checked before extraction. No system Python or package environment is modified.

The Homebrew Formula and WinGet manifests are generated **only after all four actual platform archives have been built and SHA256-verified**. No placeholder URL or checksum is committed. `scripts/make_release_metadata.py` writes `dist/release/release-manifest.json` and `SHA256SUMS.txt`; both package-manager generators read that single manifest. The generated Formula belongs in `pikachu-cxy/homebrew-tap`; the WinGet YAML belongs in a later `microsoft/winget-pkgs` submission. Neither external repository is changed by this project.

The tag-only release workflow validates each native archive before creating a draft GitHub Release and publishes the draft only after all assets upload. Uninstalling the Runtime does not remove the user data directory, managed scanners, scan history, or Trivy DB.

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

1. Review the four native CI verification records and tag the approved feature
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
