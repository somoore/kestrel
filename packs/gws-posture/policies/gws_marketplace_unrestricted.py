# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-marketplace-unrestricted"
TITLE = "Google Workspace Marketplace allows any app installation"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The Cloud Identity Policy API reports that Google Workspace Marketplace app access is "
    "set to allow all apps. Users can install any Marketplace application without admin approval. "
    "CISA SCuBA requires restricting Marketplace to approved apps (GWS.COMMONCONTROLS.11.1v1)."
)
REMEDIATION = (
    "In Google Admin console → Apps → Google Workspace Marketplace apps → Settings, "
    "set app access to 'Allow users to install and run only apps from the approved list' "
    "and curate a list of approved applications."
)
COMPLIANCE = {"cisa": ["GWS-11"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-1"]}
REQUIRES = ["google_workspace:policy_settings"]

# ALLOW_ALL is the only level that lets users install any app.
RESTRICTED_LEVELS = {"ALLOW_LISTED_APPS", "ALLOW_NONE"}


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "workspace_marketplace.apps_access_options":
        return True
    value = setting.get("value") or {}
    return str(value.get("accessLevel") or "").upper() in RESTRICTED_LEVELS


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "access_level": (setting.get("value") or {}).get("accessLevel"),
        "application.name": application.get("name"),
    }
