# WinGet schemas

These unmodified 1.10.0 schemas come from the Microsoft winget-cli repository:
https://github.com/microsoft/winget-cli/tree/master/schemas/JSON/manifests/v1.10.0

The original MIT license is retained as `LICENSE`. They are build and validation
inputs; they are not copied into the Runtime bundle. Validation requires no
network access. The schema's `ManifestType` and `ManifestVersion` are checked in
addition to Runtime package identity, version, artifact URL and SHA256.
