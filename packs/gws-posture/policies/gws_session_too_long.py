# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
POLICY_ID = "gws-session-too-long"
TITLE = "Google Workspace session length exceeds 12 hours without re-authentication"
SEVERITY = "medium"
RESOURCE_TYPE = "tenant_setting"
DESCRIPTION = (
    "The Cloud Identity Policy API reports a session re-authentication interval of more "
    "than 12 hours. Long sessions increase the window for session hijacking after "
    "a user's workstation is left unattended or a token is stolen. CISA SCuBA requires "
    "re-authentication after no more than 12 hours (GWS.COMMONCONTROLS.4.1v1)."
)
REMEDIATION = "In Google Admin console → Security → Google session control, set the session length to 12 hours or fewer."
COMPLIANCE = {"cisa": ["GWS-04"], "soc2": ["CC6.1"], "nist_csf": ["PR.AC-7"]}
REQUIRES = ["google_workspace:policy_settings"]

MAX_SESSION_HOURS = 12


def duration_hours(duration):
    """Session length in hours. A missing value means 0; a value
    `duration_seconds` cannot read raises rather than passing as 0 hours."""
    return (duration_seconds(duration) or 0) / 3600


def policy(resource):
    application = resource.get("application") or {}
    setting = resource.get("setting") or {}
    if application.get("type") != "google_workspace":
        return True
    if setting.get("key") != "security.session_controls":
        return True
    value = setting.get("value") or {}
    return duration_hours(value.get("webSessionDuration")) <= MAX_SESSION_HOURS


def evidence(resource):
    setting = resource.get("setting") or {}
    application = resource.get("application") or {}
    value = setting.get("value") or {}
    return {
        "setting.key": setting.get("key"),
        "session_length": value.get("webSessionDuration"),
        "session_hours": duration_hours(value.get("webSessionDuration")),
        "max_allowed_hours": MAX_SESSION_HOURS,
        "application.name": application.get("name"),
    }
