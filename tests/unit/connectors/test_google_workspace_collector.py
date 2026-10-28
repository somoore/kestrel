# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""GoogleWorkspaceCollector degradation and the token refresh seam.

A delegated admin without the role-management or Drive privilege used to fail
the whole run; Reports was skipped silently. Every optional family is now
recorded under its own name so a PARTIAL_FAILURE run says what is missing.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from kestrel_connector_google_workspace.client import GoogleWorkspaceClient
from kestrel_connector_google_workspace.collector import GoogleWorkspaceCollector

DOMAIN = "acme.test"


def _http_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://www.googleapis.com/x")
    response = httpx.Response(status, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


class _CannedTransport:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append(path)
        for prefix, value in sorted(self.responses.items(), key=lambda kv: -len(kv[0])):
            if path.startswith(prefix):
                if isinstance(value, BaseException):
                    raise value
                return value
        raise AssertionError(f"unexpected path {path}")

    def paginate(self, method: str, path: str, **kwargs: Any) -> Any:
        yield self.request(method, path, **kwargs)


_USER = {"id": "1", "primaryEmail": "ada@acme.test", "name": {"fullName": "Ada"}, "isAdmin": True}
_BASE: dict[str, Any] = {
    "/admin/directory/v1/customers/my_customer": {"id": "C01234abc", "customerDomain": DOMAIN},
    "/admin/directory/v1/customer/my_customer/domains/acme.test": {"domainName": DOMAIN, "isPrimary": True},
    "/admin/directory/v1/customer/my_customer/domains": {
        "domains": [
            {
                "domainName": DOMAIN,
                "isPrimary": True,
                "verified": True,
                "domainAliases": [{"domainAliasName": "acme-alias.test"}],
            }
        ]
    },
    "/admin/directory/v1/customer/my_customer/orgunits": {
        "organizationUnits": [{"orgUnitId": "id:eng", "orgUnitPath": "/Engineering", "parentOrgUnitId": "id:root"}]
    },
    "/groups/v1/groups/eng%40acme.test": {"email": "eng@acme.test", "allowExternalMembers": "true"},
    "/admin/directory/v1/users": {
        "users": [
            _USER,
            {"id": "2", "primaryEmail": "bob@acme.test"},
            {"id": "3", "primaryEmail": "gone@acme.test", "suspended": True},
        ]
    },
    "/admin/directory/v1/users/1/tokens": {"items": [{"clientId": "c-slack", "displayText": "Slack", "scopes": ["openid"]}]},
    "/admin/directory/v1/users/2/tokens": {
        "items": [{"clientId": "c-drive", "displayText": "Drive Sync", "scopes": ["https://www.googleapis.com/auth/drive"]}]
    },
    "/admin/directory/v1/groups/G1/members": {
        "members": [
            {"id": "1", "email": "ada@acme.test", "role": "MEMBER", "type": "USER"},
            {"id": "2", "email": "bob@acme-alias.test", "role": "MEMBER", "type": "USER"},
            {"id": "77", "email": "vendor@partner.test", "role": "MEMBER", "type": "USER"},
        ]
    },
    "/admin/directory/v1/groups": {"groups": [{"id": "G1", "email": "eng@acme.test", "name": "Engineering"}]},
    "/admin/directory/v1/customer/my_customer/roles": {"items": [{"roleId": "R1", "roleName": "_SEED_ADMIN_ROLE"}]},
    "/admin/directory/v1/customer/my_customer/roleassignments": {
        "items": [{"roleAssignmentId": "A1", "roleId": "R1", "assignedTo": "1"}]
    },
    "/drive/v3/drives": {"drives": [{"id": "D1", "name": "Finance"}]},
    "/drive/v3/drives/D1/permissions": {"permissions": [{"id": "P1", "type": "user", "emailAddress": "ada@acme.test"}]},
    "/admin/reports/v1/activity/users/all/applications/token": {"items": []},
    "/admin/reports/v1/activity/users/all/applications/login": {
        "items": [
            {
                "id": {"time": "2026-08-30T02:11:00.000Z", "uniqueQualifier": "2001"},
                "actor": {"email": "a@acme.test"},
                "events": [],
            }
        ]
    },
    # v0.2 stubs so _drain still works in pre-v0.2 tests
    "https://cloudidentity.googleapis.com/v1/policies?customer=customers/my_customer&pageSize=100": {"policies": []},
    "/admin/directory/v1/customer/my_customer/devices/mobile?maxResults=100": {"mobiledevices": []},
    "/admin/directory/v1/customer/my_customer/devices/chromeos?maxResults=100": {"chromeosdevices": []},
    "https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=100": {"alerts": []},
    "https://cloudidentity.googleapis.com/v1/inboundSamlSsoProfiles?parent=customers/my_customer&pageSize=50": {
        "inboundSamlSsoProfiles": []
    },
    (
        "https://cloudidentity.googleapis.com/v1/inboundSsoAssignments"
        "?filter=customer%3D%3Dcustomers%2Fmy_customer&pageSize=50"
    ): {"inboundSsoAssignments": []},
    "/admin/reports/v1/activity/users/all/applications/admin": {"items": []},
    "/admin/reports/v1/activity/users/all/applications/drive": {"items": []},
    "/admin/reports/v1/activity/users/all/applications/saml": {"items": []},
    "/admin/reports/v1/activity/users/all/applications/user_accounts": {"items": []},
    "/admin/reports/v1/activity/users/all/applications/groups": {"items": []},
    "/admin/reports/v1/activity/users/all/applications/mobile": {"items": []},
}


def _collector(overrides: dict[str, Any] | None = None) -> tuple[GoogleWorkspaceCollector, _CannedTransport]:
    transport = _CannedTransport({**_BASE, **(overrides or {})})
    return GoogleWorkspaceCollector(GoogleWorkspaceClient(transport, domain=DOMAIN)), transport


def _drain(collector: GoogleWorkspaceCollector) -> dict[str, int]:
    return {object_type: len(list(collector.collect(object_type))) for object_type in collector.discover()}


def test_a_full_run_records_no_skips() -> None:
    collector, _ = _collector()
    counts = _drain(collector)
    assert counts["user"] == 3
    assert counts["user_token"] == 2
    assert counts["group_member"] == 3
    assert counts["group_setting"] == 1
    assert counts["org_unit"] == 1
    assert counts["domain_list"] == 1
    assert counts["role_assignment"] == 1
    assert counts["drive_permission"] == 1
    assert collector.skipped_object_types == {}


@pytest.mark.parametrize(
    ("object_type", "path"),
    [
        ("shared_drive", "/drive/v3/drives"),
        ("login_activity", "/admin/reports/v1/activity/users/all/applications/login"),
    ],
)
def test_a_gated_optional_family_is_recorded_not_raised(object_type: str, path: str) -> None:
    collector, _ = _collector({path: _http_error(403)})
    counts = _drain(collector)
    assert counts[object_type] == 0
    assert counts["user"] == 3
    assert collector.skipped_object_types[object_type] == "permission"


def test_a_gated_group_membership_is_a_sub_family_skip() -> None:
    collector, _ = _collector({"/admin/directory/v1/groups/G1/members": _http_error(403)})
    counts = _drain(collector)
    assert counts["group"] == 1
    assert counts["group_member"] == 0
    assert collector.skipped_object_types == {"group_member.members": "permission"}


def test_the_directory_itself_still_fails_the_run() -> None:
    collector, _ = _collector({"/admin/directory/v1/users": _http_error(403)})
    with pytest.raises(httpx.HTTPStatusError):
        list(collector.collect("user"))
    assert collector.skipped_object_types == {}


def test_a_throttled_family_raises_rather_than_reporting_zero_rows() -> None:
    collector, _ = _collector({"/drive/v3/drives": _http_error(429)})
    with pytest.raises(httpx.HTTPStatusError):
        list(collector.collect("shared_drive"))
    assert collector.skipped_object_types == {}


def test_live_transport_re_mints_the_token_on_401(monkeypatch: pytest.MonkeyPatch) -> None:
    from kestrel_connector_google_workspace import auth

    minted: list[str] = []

    def fake_mint(**kwargs: Any) -> str:
        minted.append(f"tok-{len(minted) + 1}")
        return minted[-1]

    # LiveHTTPTransport validates base_url via DNS; unit tests must not depend
    # on outbound resolution (sandboxed CI / offline agents).
    monkeypatch.setattr("kestrel.connectors.sdk.transport.validate_connector_url", lambda *a, **k: None)
    monkeypatch.setattr(auth, "mint_access_token_from_service_account", fake_mint)
    transport = auth.build_live_transport({"service_account_json": "{}", "delegated_admin_email": "admin@acme.test"})

    assert transport.client.headers["Authorization"] == "Bearer tok-1"
    assert transport._auth_refresh is not None
    refreshed = transport._auth_refresh()
    assert refreshed == {"Authorization": "Bearer tok-2"}


def test_gated_role_management_falls_back_to_directory_admin_flags() -> None:
    collector, _ = _collector(
        {
            "/admin/directory/v1/customer/my_customer/roles": _http_error(403),
            "/admin/directory/v1/customer/my_customer/roleassignments": _http_error(403),
        }
    )
    roles = list(collector.collect("admin_role"))
    assignments = list(collector.collect("role_assignment"))

    assert {r.provider_id for r in roles} == {"flag:super_admin", "flag:delegated_admin"}
    assert all(r.payload["synthetic_from_user_flag"] for r in roles)
    # Ada is isAdmin, so she is assigned the stand-in Super Admin role.
    assert [(a.payload["roleId"], a.payload["assignedTo"]) for a in assignments] == [("flag:super_admin", "1")]
    # Reduced coverage is still reported: the real assignment list was unreadable.
    assert collector.skipped_object_types == {"admin_role": "permission", "role_assignment": "permission"}


def test_external_membership_is_decided_against_every_customer_domain_and_alias() -> None:
    collector, _ = _collector()
    by_id = {m.payload["id"]: m.payload for m in collector.collect("group_member")}
    assert by_id["1"]["is_external"] is False
    assert by_id["1"]["is_directory_user"] is True
    # An alias domain is still inside the tenant.
    assert by_id["2"]["is_external"] is False
    assert by_id["2"]["is_directory_user"] is True
    assert by_id["77"]["is_external"] is True
    assert by_id["77"]["is_directory_user"] is False


def test_a_gated_domains_list_still_decides_external_against_the_primary_domain() -> None:
    collector, _ = _collector({"/admin/directory/v1/customer/my_customer/domains": _http_error(403)})
    by_id = {m.payload["id"]: m.payload for m in collector.collect("group_member")}
    assert by_id["1"]["is_external"] is False
    assert by_id["2"]["is_external"] is True  # alias unknown without the domains list
    # The approximation is recorded, so the run is PARTIAL rather than a green
    # run whose external-member findings are guesses.
    assert collector.skipped_object_types["group_member.domains"] == "permission"
    assert list(collector.collect("domain_list")) == []
    assert collector.skipped_object_types["domain_list"] == "permission"


@pytest.mark.parametrize("status", [429, 500])
def test_a_transient_failure_on_the_domains_list_fails_the_run_rather_than_guessing(status: int) -> None:
    # A 429 or 500 here used to fall back to the primary domain silently: every
    # alias-domain member became "external" on a run that reported SUCCESS.
    collector, _ = _collector({"/admin/directory/v1/customer/my_customer/domains": _http_error(status)})
    with pytest.raises(httpx.HTTPStatusError):
        list(collector.collect("group_member"))
    assert "group_member.domains" not in collector.skipped_object_types


def test_gated_group_settings_are_recorded_once() -> None:
    collector, _ = _collector({"/groups/v1/groups/eng%40acme.test": _http_error(403)})
    assert list(collector.collect("group_setting")) == []
    assert collector.skipped_object_types == {"group_setting": "permission"}


def test_users_carry_their_org_unit_id() -> None:
    collector, _ = _collector({"/admin/directory/v1/users": {"users": [{**_USER, "orgUnitPath": "/Engineering"}]}})
    user = next(iter(collector.collect("user")))
    assert user.payload["org_unit_id"] == "id:eng"


def test_user_tokens_skip_suspended_users_and_carry_the_user() -> None:
    collector, transport = _collector()
    tokens = list(collector.collect("user_token"))
    assert {t.payload["user_id"] for t in tokens} == {"1", "2"}
    assert all("/users/3/tokens" not in call for call in transport.calls)
    assert tokens[0].provider_id == "1:c-slack"
    assert tokens[0].payload["user_email"] == "ada@acme.test"


def test_a_tenant_wide_token_gate_is_recorded_once_from_the_probe_user() -> None:
    collector, transport = _collector({"/admin/directory/v1/users/1/tokens": _http_error(403)})
    assert list(collector.collect("user_token")) == []
    assert collector.skipped_object_types == {"user_token": "permission"}
    # The remaining users were never asked.
    assert not any("/users/2/tokens" in call for call in transport.calls)


def test_a_single_unreadable_user_is_a_sub_family_skip() -> None:
    collector, _ = _collector({"/admin/directory/v1/users/2/tokens": _http_error(404)})
    tokens = list(collector.collect("user_token"))
    assert [t.payload["user_id"] for t in tokens] == ["1"]
    assert collector.skipped_object_types == {"user_token.users": "http_404"}


def test_login_activity_is_cursored_on_start_time() -> None:
    from datetime import UTC, datetime

    collector, transport = _collector()
    rows = list(collector.collect("login_activity", since=datetime(2026, 8, 1, tzinfo=UTC)))
    assert [r.provider_id for r in rows] == ["login:2001"]
    assert any(
        "applications/login?" in call and "startTime=2026-08-01T00%3A00%3A00.000Z" in call for call in transport.calls
    )


def test_gated_login_activity_is_recorded() -> None:
    collector, _ = _collector({"/admin/reports/v1/activity/users/all/applications/login": _http_error(403)})
    assert list(collector.collect("login_activity")) == []
    assert collector.skipped_object_types == {"login_activity": "permission"}


# ---------------------------------------------------------------------------
# v0.2 collector tests
# ---------------------------------------------------------------------------

_V02_STUBS: dict[str, Any] = {
    "/admin/directory/v1/customers/my_customer": {
        "id": "C01234abc",
        "customerDomain": DOMAIN,
        "customerCreationTime": "2020-01-01T00:00:00.000Z",
    },
    "https://cloudidentity.googleapis.com/v1/policies?customer=customers/my_customer&pageSize=100": {
        "policies": [
            {
                "name": "policies/e1000000000002",
                "customer": "customers/C01234",
                "policyQuery": {
                    "query": "entity.org_units.exists(orgUnit, orgUnit.org_unit_id == orgUnitId('ou-eng'))",
                    "orgUnit": "orgUnits/ou-eng",
                    "group": "",
                    "sortOrder": 2.0,
                },
                "setting": {
                    "type": "settings/security.two_step_verification_enforcement",
                    "value": {"enforcedFrom": "2024-03-01T00:00:00Z"},
                },
                "type": "ADMIN",
            }
        ]
    },
    "/admin/directory/v1/customer/my_customer/devices/mobile?maxResults=100": {
        "mobiledevices": [
            {
                "deviceId": "mob-001",
                "email": ["grace@acme.test"],
                "name": ["Grace's iPhone"],
                "type": "IOS",
                "os": "iOS 17.5",
                "status": "APPROVED",
                "deviceCompromisedStatus": "COMPROMISED",
                "encryptionStatus": "ENCRYPTED",
            }
        ]
    },
    "/admin/directory/v1/customer/my_customer/devices/chromeos?maxResults=100": {
        "chromeosdevices": [
            {
                "deviceId": "cros-001",
                "serialNumber": "SN-001",
                "annotatedUser": "ada@acme.test",
                "osVersion": "119.0.6045.105",
                "status": "ACTIVE",
            }
        ]
    },
    "https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=100": {
        "alerts": [
            {
                "alertId": "alert-001",
                "type": "Suspicious login",
                "source": "Google identity",
                "createTime": "2026-09-01T12:00:00.000Z",
                "metadata": {"severity": "HIGH", "status": "OPEN"},
            }
        ]
    },
    "https://cloudidentity.googleapis.com/v1/inboundSamlSsoProfiles?parent=customers/my_customer&pageSize=50": {
        "inboundSamlSsoProfiles": [
            {
                "name": "inboundSamlSsoProfiles/acme-okta",
                "displayName": "Acme Okta",
                "idpConfig": {
                    "entityId": "http://www.okta.com/exkacme1234567",
                    "singleSignOnServiceUri": "https://acme.okta.com/sso/saml",
                },
            }
        ]
    },
    (
        "https://cloudidentity.googleapis.com/v1/inboundSsoAssignments"
        "?filter=customer%3D%3Dcustomers%2Fmy_customer&pageSize=50"
    ): {
        "inboundSsoAssignments": [
            {
                "name": "inboundSsoAssignments/root",
                "ssoMode": "SSO_OFF",
                "targetOrgUnit": "orgUnits/id:ou-root",
            }
        ]
    },
    "/admin/reports/v1/activity/users/all/applications/admin": {
        "items": [
            {
                "id": {"time": "2026-09-01T08:00:00.000Z", "uniqueQualifier": "3001"},
                "actor": {"email": "ada@acme.test"},
                "events": [{"name": "GRANT_ADMIN_PRIVILEGE", "parameters": []}],
            }
        ]
    },
    "/admin/reports/v1/activity/users/all/applications/drive": {"items": []},
    "/admin/reports/v1/activity/users/all/applications/saml": {"items": []},
    "/admin/reports/v1/activity/users/all/applications/user_accounts": {"items": []},
    "/admin/reports/v1/activity/users/all/applications/groups": {"items": []},
    "/admin/reports/v1/activity/users/all/applications/mobile": {"items": []},
}


def _collector_v02(overrides: dict[str, Any] | None = None) -> tuple[GoogleWorkspaceCollector, _CannedTransport]:
    transport = _CannedTransport({**_BASE, **_V02_STUBS, **(overrides or {})})
    return GoogleWorkspaceCollector(GoogleWorkspaceClient(transport, domain=DOMAIN)), transport


def test_customer_emits_one_raw_object() -> None:
    collector, _ = _collector_v02()
    rows = list(collector.collect("customer"))
    assert len(rows) == 1
    assert rows[0].object_type == "customer"
    assert rows[0].payload["id"] == "C01234abc"


def test_policy_collects_policy_raw_objects() -> None:
    collector, _ = _collector_v02()
    rows = list(collector.collect("policy"))
    assert len(rows) == 1
    assert rows[0].object_type == "policy"
    assert rows[0].provider_id == "policies/e1000000000002"
    # The payload is passed through untouched: the setting name stays under
    # `setting.type` and the top-level `type` stays the policy kind.
    assert rows[0].payload["setting"]["type"] == "settings/security.two_step_verification_enforcement"
    assert rows[0].payload["type"] == "ADMIN"


def test_mobile_device_collects_with_compromised_flag() -> None:
    collector, _ = _collector_v02()
    rows = list(collector.collect("mobile_device"))
    assert len(rows) == 1
    assert rows[0].payload["deviceId"] == "mob-001"
    assert rows[0].payload["deviceCompromisedStatus"] == "COMPROMISED"


def test_chromeos_device_collects() -> None:
    collector, _ = _collector_v02()
    rows = list(collector.collect("chromeos_device"))
    assert len(rows) == 1
    assert rows[0].payload["deviceId"] == "cros-001"


def test_alert_collects_individual_and_count_summary() -> None:
    collector, _ = _collector_v02()
    rows = list(collector.collect("alert"))
    # One individual alert + one count summary = 2
    assert len(rows) == 2
    types = {r.payload.get("is_count_summary", False) for r in rows}
    assert True in types  # count summary present
    assert False in types  # individual alert present


def test_inbound_sso_profile_collects() -> None:
    collector, _ = _collector_v02()
    rows = list(collector.collect("inbound_sso_profile"))
    assert len(rows) == 1
    assert rows[0].payload["displayName"] == "Acme Okta"


def test_inbound_sso_assignment_collects() -> None:
    collector, _ = _collector_v02()
    rows = list(collector.collect("inbound_sso_assignment"))
    assert len(rows) == 1
    assert rows[0].payload["ssoMode"] == "SSO_OFF"


def test_admin_activity_collects_events() -> None:
    collector, _ = _collector_v02()
    rows = list(collector.collect("admin_activity"))
    assert len(rows) == 1
    assert rows[0].object_type == "admin_activity"


def test_admin_activity_is_cursored_on_start_time() -> None:
    from datetime import UTC, datetime

    collector, transport = _collector_v02()
    list(collector.collect("admin_activity", since=datetime(2026, 8, 1, tzinfo=UTC)))
    assert any(
        "applications/admin?" in call and "startTime=2026-08-01T00%3A00%3A00.000Z" in call for call in transport.calls
    )


@pytest.mark.parametrize(
    ("object_type", "path_prefix"),
    [
        ("policy", "https://cloudidentity.googleapis.com/v1/policies"),
        ("mobile_device", "/admin/directory/v1/customer/my_customer/devices/mobile"),
        ("chromeos_device", "/admin/directory/v1/customer/my_customer/devices/chromeos"),
        ("alert", "https://alertcenter.googleapis.com/v1beta1/alerts"),
        ("inbound_sso_profile", "https://cloudidentity.googleapis.com/v1/inboundSamlSsoProfiles"),
    ],
)
def test_v02_optional_family_is_skipped_on_403(object_type: str, path_prefix: str) -> None:
    # build overrides keyed on the exact path in the stub
    override_key = next(k for k in _V02_STUBS if k.startswith(path_prefix))
    collector, _ = _collector_v02({override_key: _http_error(403)})
    rows = list(collector.collect(object_type))
    assert rows == [] or all(r.payload.get("is_count_summary") for r in rows)  # count summary may still emit
    assert collector.skipped_object_types.get(object_type) == "permission"
