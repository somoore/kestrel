# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-drive-external-sharing-enabled"
TITLE = "Google Workspace Drive allows external sharing without domain restrictions"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The Cloud Identity Policy API reports that Drive external sharing is set to ALLOWED "
    "rather than ALLOWLISTED_DOMAINS or DISALLOWED. Users can share files with any Google account "
    "outside the organization. CISA SCuBA recommends restricting external sharing to "
    "allowlisted domains (GWS.DRIVEDOCS.1.1v1)."
)
REMEDIATION = (
    "In Google Admin console → Apps → Google Workspace → Drive and Docs → Sharing settings, "
    "set 'Sharing outside of <domain>' to 'Allowlisted domains only' and add approved "
    "partner domains, or set to 'Off' if external sharing is not required."
)
COMPLIANCE = {"cisa": ["GWS-03"], "soc2": ["CC6.7"], "nist_csf": ["PR.DS-5"]}
REQUIRES = ["google_workspace:policy_settings"]

RESTRICTED_MODES = {"DISALLOWED", "ALLOWLISTED_DOMAINS"}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "drive_and_docs.external_sharing":
        return True
    value = setting.get("value") or {}
    mode = str(value.get("externalSharingMode", "ALLOWED")).upper()
    return mode in RESTRICTED_MODES


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    value = setting.get("value") or {}
    return {
        "setting.key": setting.get("key"),
        "external_sharing_mode": value.get("externalSharingMode"),
        "application.name": application.get("name"),
    }
