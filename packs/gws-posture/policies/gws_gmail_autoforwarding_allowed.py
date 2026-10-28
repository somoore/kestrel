# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-gmail-autoforwarding-allowed"
TITLE = "Google Workspace allows Gmail auto-forwarding to external addresses"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The Cloud Identity Policy API reports that users can automatically forward all "
    "incoming Gmail to an external address. Auto-forwarding is a common exfiltration "
    "technique and a business email compromise indicator. Disabling it forces any "
    "forwarding rule to be reviewed and set by an admin."
)
REMEDIATION = (
    "In Google Admin console → Apps → Google Workspace → Gmail → End User Access, "
    "uncheck 'Allow users to automatically forward incoming email to another address'. "
    "Review existing forwarding filters in the Admin console before disabling."
)
COMPLIANCE = {"cisa": ["GWS-02"], "soc2": ["CC6.7"], "nist_csf": ["PR.DS-5"]}
REQUIRES = ["google_workspace:policy_settings"]


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "gmail.auto_forwarding":
        return True
    value = setting.get("value") or {}
    return not bool(value.get("enableAutoForwarding", False))


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "auto_forwarding_enabled": (setting.get("value") or {}).get("enableAutoForwarding"),
        "application.name": application.get("name"),
    }
