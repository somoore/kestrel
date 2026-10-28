# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-less-secure-apps-allowed"
TITLE = "Google Workspace allows less-secure app access"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "Less-secure apps use basic username/password authentication and bypass 2-Step Verification. "
    "The Cloud Identity Policy API reports that LSA access is enabled for this tenant or OU. "
    "CISA SCuBA requires LSA to be blocked (GWS.COMMONCONTROLS.10.5v1)."
)
REMEDIATION = (
    "In Google Admin console → Security → Less secure app access, turn off "
    "'Allow users to manage their access to less secure apps'. Modern IMAP/SMTP clients "
    "use OAuth; migrate any remaining basic-auth integrations first."
)
COMPLIANCE = {"cisa": ["GWS-10"], "cis": ["3.2"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-7"]}
REQUIRES = ["google_workspace:policy_settings"]


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "security.less_secure_apps":
        return True
    value = setting.get("value") or {}
    return not bool(value.get("allowLessSecureApps", False))


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "setting.value": setting.get("value"),
        "application.name": application.get("name"),
    }
