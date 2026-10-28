# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-super-admin-recovery-enabled"
TITLE = "Super Admin self-recovery is enabled"
SEVERITY = "high"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The Cloud Identity Policy API reports that Super Admins can recover their own accounts "
    "using personal recovery information. An attacker who compromises a Super Admin's recovery "
    "contact (phone or email) can lock out the organization. CISA SCuBA requires disabling "
    "admin self-recovery (GWS.COMMONCONTROLS.8.1v1)."
)
REMEDIATION = (
    "In Google Admin console → Security → Account recovery → Super Admin recovery, "
    "disable self-recovery for admins. Establish a break-glass procedure with peer "
    "admin recovery instead of personal recovery contacts."
)
COMPLIANCE = {"cisa": ["GWS-08"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-7"]}
REQUIRES = ["google_workspace:policy_settings"]


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "security.super_admin_account_recovery":
        return True
    value = setting.get("value") or {}
    return not bool(value.get("enableAccountRecovery", False))


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    return {
        "setting.key": setting.get("key"),
        "account_recovery_enabled": (setting.get("value") or {}).get("enableAccountRecovery"),
        "application.name": application.get("name"),
    }
