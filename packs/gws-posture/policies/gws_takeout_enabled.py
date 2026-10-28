# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-takeout-enabled"
TITLE = "Google Takeout is enabled for all users"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The Cloud Identity Policy API reports that Google Takeout is enabled, allowing any user "
    "to export a copy of their data from Google services. This is a data exfiltration risk "
    "for organizations handling sensitive information. CISA SCuBA recommends disabling "
    "Takeout (GWS.COMMONCONTROLS.12.1v1)."
)
REMEDIATION = (
    "In Google Admin console → Account → Account settings → Google Takeout, "
    "uncheck 'Users can manage Google Takeout' or restrict it to specific OUs."
)
COMPLIANCE = {"cisa": ["GWS-12"], "soc2": ["CC6.7"], "nist_csf": ["PR.DS-5"]}
REQUIRES = ["google_workspace:policy_settings"]


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "takeout.service_status":
        return True
    value = setting.get("value") or {}
    return str(value.get("serviceState") or "").upper() == "DISABLED"


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "service_state": (setting.get("value") or {}).get("serviceState"),
        "application.name": application.get("name"),
    }
