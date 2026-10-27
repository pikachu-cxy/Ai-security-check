"""Engine license declarations and fail-closed distribution gates.

These declarations describe the pinned artifacts used by this release. A new
engine must supply its own reviewed metadata before automated installation.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class LicenseClass(StrEnum):
    PERMISSIVE = "PERMISSIVE"
    WEAK_COPYLEFT = "WEAK_COPYLEFT"
    STRONG_COPYLEFT = "STRONG_COPYLEFT"
    SOURCE_AVAILABLE = "SOURCE_AVAILABLE"
    COMMERCIAL = "COMMERCIAL"
    RESTRICTED = "RESTRICTED"
    UNKNOWN = "UNKNOWN"


class Permission(StrEnum):
    YES = "YES"
    WITH_OBLIGATIONS = "WITH_OBLIGATIONS"
    NO = "NO"


class LicenseAction(StrEnum):
    USE = "USE"
    AUTO_DOWNLOAD = "AUTO_DOWNLOAD"
    REDISTRIBUTE = "REDISTRIBUTE"
    BUNDLE = "BUNDLE"
    HOSTED_SERVICE = "HOSTED_SERVICE"


@dataclass(frozen=True)
class LicenseMetadata:
    license_spdx: str
    license_name: str
    license_url: str
    commercial_use_allowed: bool
    auto_download_allowed: bool
    redistribution_allowed: Permission
    bundle_allowed: Permission
    hosted_service_allowed: bool
    notice_required: bool
    source_offer_required: bool
    attribution_required: bool
    attribution_text: str
    external_license_required: bool
    license_class: LicenseClass
    copyright: str


class LicensePolicy:
    @staticmethod
    def permission(metadata: LicenseMetadata | None, action: LicenseAction) -> Permission:
        if (metadata is None or metadata.external_license_required or
                metadata.license_class in {LicenseClass.RESTRICTED, LicenseClass.UNKNOWN} or
                not metadata.commercial_use_allowed):
            return Permission.NO
        if action == LicenseAction.USE:
            return Permission.YES
        if action == LicenseAction.AUTO_DOWNLOAD:
            return Permission.YES if metadata.auto_download_allowed else Permission.NO
        if action == LicenseAction.HOSTED_SERVICE:
            return Permission.YES if metadata.hosted_service_allowed else Permission.NO
        if action == LicenseAction.REDISTRIBUTE:
            return metadata.redistribution_allowed
        if action == LicenseAction.BUNDLE:
            if metadata.redistribution_allowed == Permission.NO or metadata.bundle_allowed == Permission.NO:
                return Permission.NO
            if Permission.WITH_OBLIGATIONS in {metadata.redistribution_allowed, metadata.bundle_allowed}:
                return Permission.WITH_OBLIGATIONS
            return Permission.YES
        raise ValueError(f"Unknown license action: {action}")

    @classmethod
    def can_auto_download(cls, metadata: LicenseMetadata | None) -> bool:
        return cls.permission(metadata, LicenseAction.AUTO_DOWNLOAD) != Permission.NO

    @staticmethod
    def distribution_status(metadata: LicenseMetadata | None, action: LicenseAction = LicenseAction.BUNDLE) -> str:
        if metadata is None or metadata.external_license_required:
            return "EXTERNAL LICENSE REQUIRED" if metadata and metadata.external_license_required else "BLOCKED"
        permission = LicensePolicy.permission(metadata, action)
        return {Permission.NO: "BLOCKED", Permission.WITH_OBLIGATIONS: "REVIEWED", Permission.YES: "OK"}[permission]

    @classmethod
    def can_bundle(cls, metadata: LicenseMetadata | None) -> bool:
        return cls.permission(metadata, LicenseAction.BUNDLE) != Permission.NO


GITLEAKS_LICENSE = LicenseMetadata(
    "MIT", "MIT License", "https://github.com/gitleaks/gitleaks/blob/v8.30.0/LICENSE",
    True, True, Permission.YES, Permission.YES, True, True, False, False, "", False,
    LicenseClass.PERMISSIVE, "Copyright (c) 2019 Zachary Rice")
TRIVY_LICENSE = LicenseMetadata(
    "Apache-2.0", "Apache License 2.0", "https://github.com/aquasecurity/trivy/blob/v0.74.0/LICENSE",
    True, True, Permission.YES, Permission.YES, True, True, False, False, "", False,
    LicenseClass.PERMISSIVE, "Copyright Aqua Security and contributors")
OSV_SCANNER_LICENSE = LicenseMetadata(
    "Apache-2.0", "Apache License 2.0", "https://github.com/google/osv-scanner/blob/v2.6.0/LICENSE",
    True, True, Permission.YES, Permission.YES, True, True, False, False, "", False,
    LicenseClass.PERMISSIVE, "Copyright Google LLC and OSV-Scanner contributors")
SEMGREP_LICENSE = LicenseMetadata(
    "LGPL-2.1-only", "GNU Lesser General Public License v2.1", "https://github.com/semgrep/semgrep/blob/v1.178.0/LICENSE",
    True, True, Permission.WITH_OBLIGATIONS, Permission.WITH_OBLIGATIONS, True, True, True, False, "", False,
    LicenseClass.WEAK_COPYLEFT, "Copyright Semgrep, Inc. and contributors")
OPENGREP_LICENSE = LicenseMetadata(
    "LGPL-2.1-only", "GNU Lesser General Public License v2.1", "https://github.com/opengrep/opengrep/blob/v1.32.0/LICENSE",
    True, True, Permission.WITH_OBLIGATIONS, Permission.WITH_OBLIGATIONS, True, True, True, True,
    "OpenGrep and contributors; retain upstream LGPL license and corresponding source reference.", False,
    LicenseClass.WEAK_COPYLEFT, "Copyright OpenGrep, Semgrep and contributors")


CODEQL_FUTURE_LICENSE = LicenseMetadata(
    "LicenseRef-CodeQL", "Proprietary", "https://github.com/github/codeql-cli-binaries",
    False, False, Permission.NO, Permission.NO, False, True, False, False, "", True,
    LicenseClass.RESTRICTED, "Copyright GitHub, Inc.")


AI_INFRA_GUARD_FUTURE_ATTRIBUTION = "This product integrates AI-Infra-Guard, open-sourced by Tencent Zhuque Lab."

# The standalone bootstrap downloads a separate CPython distribution. It is
# never bundled in the Runtime artifact; upstream retains its license inventory.
MANAGED_PYTHON_LICENSE = LicenseMetadata(
    "Python-2.0 AND LicenseRef-PBS-20260211-Components",
    "CPython and python-build-standalone component licenses",
    "https://github.com/astral-sh/python-build-standalone/blob/main/docs/running.rst",
    True, True, Permission.NO, Permission.NO, False, True, False, True,
    "Preserve the downloaded Python distribution's license inventory.", False,
    LicenseClass.WEAK_COPYLEFT, "Copyright Python Software Foundation and distribution contributors")

PYINSTALLER_BOOTLOADER_LICENSE = LicenseMetadata(
    "GPL-2.0-or-later WITH Bootloader-exception", "PyInstaller bootloader license with distribution exception",
    "https://pyinstaller.org/en/v6.22.3/license.html",
    True, True, Permission.WITH_OBLIGATIONS, Permission.WITH_OBLIGATIONS, True, True, False, False, "", False,
    LicenseClass.STRONG_COPYLEFT, "Copyright PyInstaller Development Team")
