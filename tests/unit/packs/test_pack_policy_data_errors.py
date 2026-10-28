# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Pack policies fail loudly on data they cannot read.

Each policy below used to catch the parse error and answer for the author --
most of them "compliant", so a garbled timestamp or an unrecognized duration
format passed silently. They now raise `PolicyDataError`, which fails the
evaluation with a visible error (docs/policies.md, "Missing and malformed
data"). The sweep cannot express "this row must error", so the cases live here
with inline rows; nothing reads a shipped fixture.
"""

from __future__ import annotations

import pytest
from kestrel.policies.loader import load_policy_file
from kestrel.policies.packs import get_packs_dir
from kestrel.policies.runtime.helpers import PolicyDataError


def _app(app_type: str) -> dict:
    return {"type": app_type, "name": app_type}


def _setting(app_type: str, key: str, value) -> dict:
    return {"_subject_id": "s1", "application": _app(app_type), "setting": {"key": key, "value": value}}


_CASES = {
    "okta-posture/okta_dormant_admin": {
        "_subject_id": "s1",
        "application": _app("okta"),
        "roles": ["Super Administrator"],
        "identity": {"last_active_at": "last tuesday"},
    },
    "okta-posture/okta_api_token_unused": {
        "_subject_id": "s1",
        "application": _app("okta"),
        "identity": {"identity_type": "service_account", "display_name": "API token: ci", "last_active_at": "?"},
    },
    "slack-posture/slack_dormant_admin": {
        "_subject_id": "s1",
        "application": _app("slack"),
        "roles": ["Admin"],
        "identity": {"last_active_source": "login", "last_active_at": "garbled"},
    },
    "github-posture/github_activity_app_installed": {
        "_subject_id": "s1",
        "application": _app("github"),
        "event": {"action": "oauth.app.install", "occurred_at": "garbled"},
    },
    "github-posture/github_copilot_seat_inactive": _setting(
        "github", "copilot_seat:1", {"login": "ada", "last_activity_at": "garbled"}
    ),
    "github-posture/github_sso_credential_stale": _setting(
        "github", "sso_credential:1", {"login": "ada", "last_accessed_at": "garbled"}
    ),
    "gws-posture/gws_session_too_long": _setting(
        "google_workspace", "security.session_controls", {"webSessionDuration": "P1M"}
    ),
    "gws-posture/gws_ou_2sv_long_grace": _setting(
        "google_workspace", "security.two_step_verification_grace_period", {"enrollmentGracePeriod": "two weeks"}
    ),
    "slack-posture/slack_pending_app_requests": _setting("slack", "pending_app_requests", "several"),
    "okta-posture/okta_password_policy_weak": _setting("okta", "password_min_length", "twelve"),
}


@pytest.mark.parametrize(("policy", "row"), _CASES.items(), ids=_CASES.keys())
def test_malformed_value_raises_instead_of_passing(policy: str, row: dict) -> None:
    pack, stem = policy.split("/")
    loaded = load_policy_file(get_packs_dir() / pack / "policies" / f"{stem}.py")
    assert loaded.is_valid, loaded.errors

    with pytest.raises(PolicyDataError):
        loaded.compiled.policy_fn(row)
