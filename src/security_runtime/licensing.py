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
    def can_auto_download(metadata: LicenseMetadata | None) -> bool:
        return bool(metadata and metadata.auto_download_allowed and not metadata.external_license_required
                    and metadata.license_class not in {LicenseClass.RESTRICTED, LicenseClass.UNKNOWN})

    @staticmethod
    def distribution_status(metadata: LicenseMetadata | None) -> str:
        if metadata is None or metadata.external_license_required:
            return "EXTERNAL LICENSE REQUIRED" if metadata and metadata.external_license_required else "BLOCKED"
        if metadata.license_class in {LicenseClass.RESTRICTED, LicenseClass.UNKNOWN}:
            return "BLOCKED"
        if metadata.redistribution_allowed == Permission.NO or metadata.bundle_allowed == Permission.NO:
            return "BLOCKED"
        if Permission.WITH_OBLIGATIONS in {metadata.redistribution_allowed, metadata.bundle_allowed}:
            return "REVIEWED"
        return "OK"

    @classmethod
    def can_bundle(cls, metadata: LicenseMetadata | None) -> bool:
        return cls.distribution_status(metadata) in {"OK", "REVIEWED"}


GITLEAKS_LICENSE = LicenseMetadata(
    "MIT", "MIT License", "https://github.com/gitleaks/gitleaks/blob/v8.30.0/LICENSE",
    True, True, Permission.YES, Permission.YES, True, True, False, False, "", False,
    LicenseClass.PERMISSIVE, "Copyright (c) 2019 Zachary Rice")
TRIVY_LICENSE = LicenseMetadata(
    "Apache-2.0", "Apache License 2.0", "https://github.com/aquasecurity/trivy/blob/v0.74.0/LICENSE",
    True, True, Permission.YES, Permission.YES, True, True, False, False, "", False,
    LicenseClass.PERMISSIVE, "Copyright Aqua Security and contributors")
SEMGREP_LICENSE = LicenseMetadata(
    "LGPL-2.1-only", "GNU Lesser General Public License v2.1", "https://github.com/semgrep/semgrep/blob/v1.178.0/LICENSE",
    True, True, Permission.WITH_OBLIGATIONS, Permission.WITH_OBLIGATIONS, True, True, True, False, "", False,
    LicenseClass.WEAK_COPYLEFT, "Copyright Semgrep, Inc. and contributors")


CODEQL_FUTURE_LICENSE = LicenseMetadata(
    "LicenseRef-CodeQL", "Proprietary", "https://github.com/github/codeql-cli-binaries",
    False, False, Permission.NO, Permission.NO, False, True, False, False, "", True,
    LicenseClass.RESTRICTED, "Copyright GitHub, Inc.")


AI_INFRA_GUARD_FUTURE_ATTRIBUTION = "This product integrates AI-Infra-Guard, open-sourced by Tencent Zhuque Lab."
