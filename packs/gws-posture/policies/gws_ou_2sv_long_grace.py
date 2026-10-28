# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-ou-2sv-long-grace"
TITLE = "Google Workspace 2SV enrollment grace period exceeds 7 days"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The Cloud Identity Policy API reports that new users have more than 7 days to enroll "
    "in 2-Step Verification before it is required. CISA SCuBA recommends a maximum of "
    "7 days. A long grace period means compromised new accounts may never enroll."
)
REMEDIATION = (
    "In Google Admin console → Security → Authentication → 2-Step Verification, set 'Enrollment period' to 7 days or fewer."
)
COMPLIANCE = {"cisa": ["GWS-01"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-7"]}
REQUIRES = ["google_workspace:policy_settings"]

MAX_GRACE_DAYS = 7


def grace_days(grace_period):
    """Grace period in days. A missing value means no grace period; a value
    `duration_seconds` cannot read raises rather than passing as 0 days."""
    return (duration_seconds(grace_period) or 0) / 86400


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "security.two_step_verification_grace_period":
        return True
    value = setting.get("value") or {}
    grace = value.get("enrollmentGracePeriod")
    return grace_days(grace) <= MAX_GRACE_DAYS


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    value = setting.get("value") or {}
    return {
        "setting.key": setting.get("key"),
        "grace_period": value.get("enrollmentGracePeriod"),
        "grace_days": grace_days(value.get("enrollmentGracePeriod")),
        "max_allowed_days": MAX_GRACE_DAYS,
        "application.name": application.get("name"),
    }
