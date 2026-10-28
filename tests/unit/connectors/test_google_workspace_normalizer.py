# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`GoogleWorkspaceNormalizer`: pure `RawObject -> NormalizedObject` mapping,
built from hand-written payloads only (see the fixture-contract rule in
`test_connector_fixture_contract.py`).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from kestrel.connectors.sdk.base import RawObject
from kestrel_connector_google_workspace.normalizer import GoogleWorkspaceNormalizer, is_sensitive_google_scope

_NOW = datetime(2026, 8, 1, tzinfo=UTC)


def _raw(object_type: str, provider_id: str, payload: dict) -> RawObject:
    return RawObject(object_type=object_type, provider_id=provider_id, payload=payload, collected_at=_NOW)


def test_normalize_raises_for_an_unknown_object_type():
    with pytest.raises(ValueError, match="widget"):
        GoogleWorkspaceNormalizer().normalize("widget", _raw("widget", "1", {}))


def test_user_suspended_or_archived_is_reported_disabled():
    normalizer = GoogleWorkspaceNormalizer()
    suspended = _raw("user", "1", {"id": 1, "primaryEmail": "a@example.com", "suspended": True})
    archived = _raw("user", "2", {"id": 2, "primaryEmail": "b@example.com", "archived": True})
    active = _raw("user", "3", {"id": 3, "primaryEmail": "c@example.com"})

    assert normalizer.normalize("user", suspended)[0].attributes["is_disabled"] is True
    assert normalizer.normalize("user", archived)[0].attributes["is_disabled"] is True
    assert normalizer.normalize("user", active)[0].attributes["is_disabled"] is False


def test_user_display_name_prefers_full_name_then_email_then_id():
    normalizer = GoogleWorkspaceNormalizer()
    with_name = _raw("user", "1", {"id": 1, "name": {"fullName": "Full Name"}, "primaryEmail": "a@example.com"})
    email_only = _raw("user", "2", {"id": 2, "primaryEmail": "b@example.com"})
    id_only = _raw("user", "3", {"id": 3})

    assert normalizer.normalize("user", with_name)[0].attributes["display_name"] == "Full Name"
    assert normalizer.normalize("user", email_only)[0].attributes["display_name"] == "b@example.com"
    assert normalizer.normalize("user", id_only)[0].attributes["display_name"] == "3"


def test_admin_role_super_admin_is_privileged_and_others_are_not():
    normalizer = GoogleWorkspaceNormalizer()
    super_admin = _raw(
        "admin_role",
        "1",
        {"roleId": 1, "roleName": "_SEED_ADMIN_ROLE", "roleDescription": "Super Admin", "isSuperAdminRole": True},
    )
    help_desk = _raw("admin_role", "2", {"roleId": 2, "roleName": "Help Desk Admin", "isSuperAdminRole": False})

    super_role = normalizer.normalize("admin_role", super_admin)[0]
    other_role = normalizer.normalize("admin_role", help_desk)[0]

    assert super_role.attributes["is_privileged"] is True
    assert other_role.attributes["is_privileged"] is False


def test_role_name_prefers_description_only_for_builtin_underscore_roles():
    normalizer = GoogleWorkspaceNormalizer()
    builtin = _raw("admin_role", "1", {"roleId": 1, "roleName": "_SEED_ADMIN_ROLE", "roleDescription": "Super Admin"})
    custom = _raw(
        "admin_role",
        "2",
        {"roleId": 2, "roleName": "Groups Reader", "roleDescription": "Custom read-only role for group metadata"},
    )

    assert normalizer.normalize("admin_role", builtin)[0].attributes["name"] == "Super Admin"
    assert normalizer.normalize("admin_role", custom)[0].attributes["name"] == "Groups Reader"


@pytest.mark.parametrize(
    ("drive_role", "expected_level"),
    [
        ("organizer", "admin"),
        ("fileOrganizer", "admin"),
        ("writer", "write"),
        ("commenter", "read"),
        ("reader", "read"),
        ("unknownRole", "read"),
    ],
)
def test_drive_permission_role_to_permission_level(drive_role, expected_level):
    raw = _raw(
        "drive_permission",
        "1",
        {"drive_id": "d1", "role": drive_role, "type": "user", "resolved_user_id": "u1"},
    )

    grant = GoogleWorkspaceNormalizer().normalize("drive_permission", raw)[0]

    assert grant.attributes["permission_level"] == expected_level


def test_drive_permission_anyone_link_is_kept_as_an_unattributed_public_grant():
    raw = _raw("drive_permission", "1", {"drive_id": "d1", "role": "reader", "type": "anyone"})

    grant = GoogleWorkspaceNormalizer().normalize("drive_permission", raw)[0]

    assert grant.attributes["is_public_link"] is True
    assert "identity_ref" not in grant.attributes
    assert grant.relationships == []


def test_drive_permission_group_grantee_emits_an_inherited_group_edge():
    raw = _raw(
        "drive_permission",
        "1",
        {"drive_id": "d1", "role": "writer", "type": "group", "resolved_group_id": "g1"},
    )

    grant = GoogleWorkspaceNormalizer().normalize("drive_permission", raw)[0]

    assert grant.attributes["granted_via"] == "group"
    assert grant.attributes["source_group_ref"] == "g1"
    assert grant.relationships[0].access_path == "inherited_group"


def test_drive_permission_external_grantee_without_a_resolved_principal_keeps_the_email():
    raw = _raw(
        "drive_permission",
        "1",
        {"drive_id": "d1", "role": "reader", "type": "user", "emailAddress": "outsider@external.example"},
    )

    grant = GoogleWorkspaceNormalizer().normalize("drive_permission", raw)[0]

    assert grant.attributes["external_grantee"] == "outsider@external.example"
    assert grant.relationships == []


def test_domain_normalizes_camelcase_admin_sdk_aliases():
    """Only for fields the Directory API actually returns.

    This test used to hand the domain normalizer `isEnforcedIn2Sv` -- a *user*
    field that never appears on a domain payload -- and assert it produced a
    `two_step_verification_enforcement` setting. It passed because the test
    supplied the invented field itself, so it guarded the fabrication instead of
    catching it. 2SV enforcement is now emitted per identity from the real user
    field; see the subject-scoped tests below.
    """
    raw = _raw("domain", "d1", {"isPrimary": True, "verified": True})

    settings = GoogleWorkspaceNormalizer().normalize("domain", raw)
    by_key = {s.attributes["key"]: s.attributes["value"] for s in settings}

    assert by_key["is_primary"] is True
    assert by_key["verified"] is True
    assert "two_step_verification_enforcement" not in by_key


def test_user_carries_directory_admin_flags_and_org_unit():
    raw = _raw(
        "user",
        "1",
        {
            "id": 1,
            "primaryEmail": "a@example.com",
            "isAdmin": True,
            "isDelegatedAdmin": False,
            "isEnforcedIn2Sv": True,
            "orgUnitPath": "/Engineering",
            "lastLoginTime": "2026-07-20T09:14:00.000Z",
        },
    )

    attrs = GoogleWorkspaceNormalizer().normalize("user", raw)[0].attributes

    assert attrs["is_admin"] is True
    assert attrs["is_delegated_admin"] is False
    assert attrs["is_enforced_in_2sv"] is True
    assert attrs["org_unit_path"] == "/Engineering"
    assert attrs["last_active_at"] == datetime(2026, 7, 20, 9, 14, tzinfo=UTC)
    assert attrs["last_active_source"] == "login"


def test_user_never_signed_in_has_no_last_active():
    raw = _raw("user", "1", {"id": 1, "primaryEmail": "a@example.com", "lastLoginTime": "1970-01-01T00:00:00.000Z"})

    attrs = GoogleWorkspaceNormalizer().normalize("user", raw)[0].attributes

    assert attrs["last_active_at"] is None
    assert attrs["last_active_source"] is None


def test_a_flag_derived_role_is_labeled_and_privileged_only_for_super_admin():
    normalizer = GoogleWorkspaceNormalizer()
    super_admin = _raw(
        "admin_role",
        "flag:super_admin",
        {
            "roleId": "flag:super_admin",
            "roleDescription": "Super Admin",
            "isSuperAdminRole": True,
            "synthetic_from_user_flag": True,
        },
    )
    delegated = _raw(
        "admin_role",
        "flag:delegated_admin",
        {
            "roleId": "flag:delegated_admin",
            "roleDescription": "Delegated Admin",
            "isSuperAdminRole": False,
            "synthetic_from_user_flag": True,
        },
    )

    sa = normalizer.normalize("admin_role", super_admin)[0].attributes
    da = normalizer.normalize("admin_role", delegated)[0].attributes

    assert (sa["name"], sa["is_privileged"], sa["derived_from"]) == ("Super Admin", True, "directory_user_flags")
    assert (da["name"], da["is_privileged"]) == ("Delegated Admin", False)


def test_an_external_group_member_becomes_an_external_identity_with_its_membership():
    raw = _raw(
        "group_member",
        "G1:900",
        {
            "id": "900",
            "email": "vendor@partner.example.net",
            "type": "USER",
            "role": "MEMBER",
            "group_id": "G1",
            "is_external": True,
            "is_directory_user": False,
        },
    )

    objects = GoogleWorkspaceNormalizer().normalize("group_member", raw)

    assert [o.kind for o in objects] == ["identity", "group_membership"]
    identity = objects[0].attributes
    assert identity["identity_type"] == "external_identity"
    assert identity["is_external"] is True
    assert identity["source_domain"] == "partner.example.net"
    membership = objects[1]
    assert membership.attributes["identity_ref"] == "900"
    assert membership.relationships[0].properties["is_external"] is True


def test_a_directory_member_emits_only_the_membership():
    raw = _raw(
        "group_member",
        "G1:1",
        {
            "id": "1",
            "email": "a@acme.test",
            "type": "USER",
            "group_id": "G1",
            "is_external": False,
            "is_directory_user": True,
        },
    )

    objects = GoogleWorkspaceNormalizer().normalize("group_member", raw)

    assert [o.kind for o in objects] == ["group_membership"]
    assert objects[0].relationships[0].properties["is_external"] is False


def test_a_nested_group_member_is_a_group_to_group_edge_with_no_attribute_churn():
    nested = {"id": "G2", "email": "security@acme.test", "name": "Security", "description": "Security team"}
    raw = _raw(
        "group_member",
        "G1:G2",
        {"id": "G2", "email": "security@acme.test", "type": "GROUP", "group_id": "G1", "nested_group": nested},
    )

    objects = GoogleWorkspaceNormalizer().normalize("group_member", raw)
    plain = GoogleWorkspaceNormalizer().normalize("group", _raw("group", "G2", nested))

    assert [o.kind for o in objects] == ["group"]
    assert objects[0].attributes == plain[0].attributes
    edge = objects[0].relationships[0]
    assert (edge.edge_type, edge.source_ref, edge.target_ref) == ("member_of", "G2", "G1")
    assert edge.properties["nested_group"] is True


def test_a_whole_domain_member_emits_nothing():
    raw = _raw("group_member", "G1:c", {"id": "c", "type": "CUSTOMER", "group_id": "G1"})
    assert GoogleWorkspaceNormalizer().normalize("group_member", raw) == []


def test_group_settings_are_subject_scoped_and_booleans_coerced():
    raw = _raw(
        "group_setting",
        "G1",
        {
            "group_id": "G1",
            "group_email": "eng@acme.test",
            "allowExternalMembers": "true",
            "whoCanJoin": "ANYONE_CAN_JOIN",
            "whoCanPostMessage": "ANYONE_CAN_POST",
        },
    )

    objects = GoogleWorkspaceNormalizer().normalize("group_setting", raw)

    by_key = {o.attributes["key"]: o for o in objects}
    assert set(by_key) == {"group_allow_external_members", "group_who_can_join", "group_who_can_post_message"}
    external = by_key["group_allow_external_members"]
    assert external.attributes["value"] is True
    assert external.attributes["category"] == "sharing"
    assert external.attributes["subject_type"] == "group"
    assert external.attributes["subject_ref"] == "G1"
    assert external.relationships[0].edge_type == "applies_to"
    assert external.relationships[0].target_ref == "G1"


def test_org_unit_is_a_group_node_linked_to_its_parent():
    raw = _raw(
        "org_unit", "id:ou-eng", {"orgUnitId": "id:ou-eng", "orgUnitPath": "/Engineering", "parentOrgUnitId": "id:ou-root"}
    )

    obj = GoogleWorkspaceNormalizer().normalize("org_unit", raw)[0]

    assert obj.kind == "group"
    assert obj.attributes["kind"] == "org_unit"
    assert obj.attributes["name"] == "/Engineering"
    assert (obj.relationships[0].source_ref, obj.relationships[0].target_ref) == ("id:ou-eng", "id:ou-root")


def test_user_in_an_org_unit_gets_a_member_of_edge():
    raw = _raw(
        "user", "1", {"id": 1, "primaryEmail": "a@example.com", "orgUnitPath": "/Engineering", "org_unit_id": "id:ou-eng"}
    )

    obj = GoogleWorkspaceNormalizer().normalize("user", raw)[0]

    assert obj.relationships[0].edge_type == "member_of"
    assert obj.relationships[0].target_ref == "id:ou-eng"


def test_domain_list_emits_verification_and_aliases():
    raw = _raw(
        "domain_list",
        "acme.test",
        {"domainName": "acme.test", "verified": True, "domainAliases": [{"domainAliasName": "acme-corp.test"}]},
    )

    objects = GoogleWorkspaceNormalizer().normalize("domain_list", raw)

    keys = {o.attributes["key"]: o.attributes["value"] for o in objects}
    assert keys == {"domain_verified:acme.test": True, "domain_aliases:acme.test": ["acme-corp.test"]}


def test_user_token_emits_app_scopes_and_grant_with_google_scope_sensitivity():
    raw = _raw(
        "user_token",
        "1:9988-mailmerge.apps.googleusercontent.com",
        {
            "clientId": "9988-mailmerge.apps.googleusercontent.com",
            "displayText": "MailMerge Pro",
            "anonymous": True,
            "nativeApp": False,
            "scopes": ["https://mail.google.com/", "https://www.googleapis.com/auth/drive.file", "openid"],
            "user_id": "1",
            "user_email": "a@example.com",
        },
    )

    objects = GoogleWorkspaceNormalizer().normalize("user_token", raw)

    kinds = [o.kind for o in objects]
    assert kinds == ["oauth_application", "oauth_scope", "oauth_scope", "oauth_scope", "oauth_grant"]
    app = objects[0]
    assert app.provider_id == "oauth-client:9988-mailmerge.apps.googleusercontent.com"
    assert app.attributes["publisher"] == "third-party"
    assert app.attributes["is_verified"] is False
    sensitivity = {o.attributes["scope_name"]: o.attributes["is_sensitive"] for o in objects[1:4]}
    assert sensitivity == {
        "https://mail.google.com/": True,
        "https://www.googleapis.com/auth/drive.file": False,
        "openid": False,
    }
    grant = objects[-1]
    assert grant.attributes["identity_ref"] == "1"
    assert grant.relationships[0].access_path == "oauth_derived"
    assert grant.relationships[0].properties["sensitive"] is True


def test_google_scope_sensitivity_ruleset():
    assert is_sensitive_google_scope("https://www.googleapis.com/auth/drive") is True
    assert is_sensitive_google_scope("https://www.googleapis.com/auth/drive.readonly") is True
    assert is_sensitive_google_scope("https://www.googleapis.com/auth/drive.file") is False
    assert is_sensitive_google_scope("https://www.googleapis.com/auth/admin.directory.user") is True
    assert is_sensitive_google_scope("https://www.googleapis.com/auth/userinfo.email") is False
    assert is_sensitive_google_scope("") is False


def test_a_custom_role_with_a_security_privilege_is_privileged():
    normalizer = GoogleWorkspaceNormalizer()
    custom = _raw(
        "admin_role",
        "r4",
        {
            "roleId": "r4",
            "roleName": "Security Operations",
            "isSuperAdminRole": False,
            "isSystemRole": False,
            "rolePrivileges": [{"privilegeName": "SECURITY_SETTINGS"}, {"privilegeName": "USERS_RETRIEVE"}],
        },
    )
    reader = _raw(
        "admin_role",
        "r3",
        {
            "roleId": "r3",
            "roleName": "Groups Reader",
            "isSuperAdminRole": False,
            "isSystemRole": False,
            "rolePrivileges": [{"privilegeName": "GROUPS_RETRIEVE"}],
        },
    )

    ops = normalizer.normalize("admin_role", custom)[0].attributes
    ro = normalizer.normalize("admin_role", reader)[0].attributes

    assert ops["is_privileged"] is True
    assert ops["privileged_privilege_names"] == ["SECURITY_SETTINGS"]
    assert ro["is_privileged"] is False
    assert ro["privilege_names"] == ["GROUPS_RETRIEVE"]


def test_login_activity_keeps_curated_events_and_drops_successes():
    normalizer = GoogleWorkspaceNormalizer()
    suspicious = _raw(
        "login_activity",
        "login:2001",
        {
            "id": {"time": "2026-08-30T02:11:00.000Z", "uniqueQualifier": "2001"},
            "actor": {"email": "grace@acme.test", "profileId": "2"},
            "ipAddress": "203.0.113.9",
            "events": [{"name": "suspicious_login", "parameters": [{"name": "is_suspicious", "boolValue": True}]}],
        },
    )
    success = _raw(
        "login_activity",
        "login:2003",
        {
            "id": {"time": "2026-08-28T12:00:00.000Z"},
            "actor": {"email": "ada@acme.test"},
            "events": [{"name": "login_success"}],
        },
    )

    events = normalizer.normalize("login_activity", suspicious)
    assert len(events) == 1
    attrs = events[0].attributes
    assert attrs["action"] == "threat.detected"
    assert attrs["action_category"] == "threat"
    assert attrs["actor_email"] == "grace@acme.test"
    assert attrs["target_provider_id"] == "2"
    assert attrs["attributes"]["ip_address"] == "203.0.113.9"
    assert attrs["attributes"]["is_suspicious"] is True
    assert normalizer.normalize("login_activity", success) == []


# The Admin SDK Directory `domains.get` resource, verbatim. Workspace
# *configuration* is not on it and is not reachable from the Directory API at
# all -- 2SV enforcement, Drive sharing, and Calendar sharing live in the Cloud
# Identity Policy API. The connector previously emitted all three from a fixture
# that invented them, so two policies could never fire on a real tenant while
# passing every offline test.
_DIRECTORY_DOMAIN_FIELDS = frozenset(
    {"kind", "etag", "domainName", "isPrimary", "verified", "creationTime", "domainAliases"}
)


def test_domain_settings_come_only_from_fields_the_directory_api_returns():
    raw = _raw(
        "domain",
        "acme.example.com",
        {
            "kind": "admin#directory#domain",
            "etag": '"acme"',
            "domainName": "acme.example.com",
            "isPrimary": True,
            "verified": True,
            "creationTime": "1609459200000",
            "domainAliases": [],
        },
    )
    keys = {obj.attributes["key"] for obj in GoogleWorkspaceNormalizer().normalize("domain", raw)}
    # Every emitted setting must be derivable from a real response field.
    assert keys <= {"is_primary", "verified"}, (
        f"domain settings {sorted(keys - {'is_primary', 'verified'})} are not derivable from "
        f"the Directory domains.get resource ({sorted(_DIRECTORY_DOMAIN_FIELDS)})"
    )


def test_a_domain_payload_without_invented_fields_emits_no_configuration_settings():
    """Guard the specific regression: a real payload must not yield 2SV or sharing."""
    raw = _raw("domain", "acme.example.com", {"domainName": "acme.example.com", "isPrimary": True, "verified": True})
    keys = {obj.attributes["key"] for obj in GoogleWorkspaceNormalizer().normalize("domain", raw)}
    for invented in ("two_step_verification_enforcement", "drive_sharing_for_non_members", "external_calendar_sharing"):
        assert invented not in keys


def test_two_step_verification_enforcement_is_scoped_to_the_account_it_governs():
    """`isEnforcedIn2Sv` is a per-user Directory field; there is no domain-level one."""
    raw = _raw(
        "user",
        "100",
        {
            "id": "100",
            "primaryEmail": "ada@acme.example.com",
            "name": {"fullName": "Ada Lovelace"},
            "isEnrolledIn2Sv": True,
            "isEnforcedIn2Sv": False,
        },
    )
    objects = GoogleWorkspaceNormalizer().normalize("user", raw)
    settings = [o for o in objects if o.kind == "setting"]
    assert len(settings) == 1
    setting = settings[0]
    assert setting.attributes["key"] == "two_step_verification_enforced"
    assert setting.attributes["value"] is False
    # Subject-scoped, so a finding names the account rather than the tenant.
    assert setting.attributes["subject_type"] == "identity"
    assert setting.attributes["subject_ref"] == "100"
    assert [(r.edge_type, r.target_ref) for r in setting.relationships] == [("applies_to", "100")]


def test_enforced_accounts_report_enforcement_true():
    raw = _raw("user", "101", {"id": "101", "primaryEmail": "g@acme.example.com", "isEnforcedIn2Sv": True})
    settings = [o for o in GoogleWorkspaceNormalizer().normalize("user", raw) if o.kind == "setting"]
    assert settings[0].attributes["value"] is True


# ---------------------------------------------------------------------------
# v0.2 normalizer tests
# ---------------------------------------------------------------------------


def _policy(setting_type, value, *, org_unit="orgUnits/ou-eng", group="", policy_type="ADMIN"):
    """A Policy resource as the Cloud Identity API returns it: the setting name
    is `setting.type` with a `settings/` prefix, the scope is `policyQuery`,
    and the top-level `type` is the policy kind, not the setting name."""
    return _raw(
        "policy",
        "policies/e1",
        {
            "name": "policies/e1",
            "customer": "customers/C01234",
            "policyQuery": {
                "query": "entity.org_units.exists(orgUnit, orgUnit.org_unit_id == orgUnitId('ou-eng'))",
                "orgUnit": org_unit,
                "group": group,
                "sortOrder": 1.0,
            },
            "setting": {"type": f"settings/{setting_type}", "value": value},
            "type": policy_type,
        },
    )


def test_policy_ou_scoped_emits_setting_with_subject_and_applies_to_edge():
    raw = _policy("security.two_step_verification_enforcement", {"enforcedFrom": "2024-03-01T00:00:00Z"})

    objects = GoogleWorkspaceNormalizer().normalize("policy", raw)

    assert len(objects) == 1
    obj = objects[0]
    assert obj.kind == "setting"
    # `settings/` is stripped so the key matches the documented setting name.
    assert obj.attributes["key"] == "security.two_step_verification_enforcement"
    assert obj.provider_id == "policy:id:ou-eng:security.two_step_verification_enforcement"
    # `orgUnits/<id>` becomes the Directory API's `id:<id>`, the org_unit row's provider id.
    assert obj.attributes["subject_type"] == "group"
    assert obj.attributes["subject_ref"] == "id:ou-eng"
    assert obj.attributes["label"] == "2-Step Verification enforcement (OU:id:ou-eng)"
    assert obj.attributes["value"] == {"enforcedFrom": "2024-03-01T00:00:00Z"}
    assert obj.attributes["value_type"] == "object"
    assert obj.relationships[0].edge_type == "applies_to"
    assert obj.relationships[0].target_ref == "id:ou-eng"


def test_policy_top_level_type_is_the_policy_kind_not_the_setting_name():
    """The API's top-level `type` is ADMIN or SYSTEM. Reading it as the setting
    name keyed every live policy `ADMIN`, so no pack policy ever matched."""
    for kind in ("ADMIN", "SYSTEM"):
        raw = _policy("gmail.auto_forwarding", {"enableAutoForwarding": True}, policy_type=kind)
        obj = GoogleWorkspaceNormalizer().normalize("policy", raw)[0]
        assert obj.attributes["key"] == "gmail.auto_forwarding"


def test_policy_group_scoped_names_the_group_not_the_org_unit():
    raw = _policy("gmail.imap_access", {"enableImapAccess": False}, group="groups/200000000000000000001")

    obj = GoogleWorkspaceNormalizer().normalize("policy", raw)[0]

    assert obj.attributes["subject_type"] == "group"
    assert obj.attributes["subject_ref"] == "200000000000000000001"
    assert obj.provider_id == "policy:200000000000000000001:gmail.imap_access"
    assert obj.attributes["label"] == "Gmail IMAP access (group:200000000000000000001)"
    assert obj.relationships[0].target_ref == "200000000000000000001"


def test_policy_without_a_scope_is_tenant_level():
    raw = _raw(
        "policy",
        "policies/e2",
        {"setting": {"type": "settings/gmail.auto_forwarding", "value": {"enableAutoForwarding": True}}},
    )

    obj = GoogleWorkspaceNormalizer().normalize("policy", raw)[0]

    assert obj.provider_id == "policy:tenant:gmail.auto_forwarding"
    assert "subject_type" not in obj.attributes
    assert "subject_ref" not in obj.attributes
    assert obj.relationships == []


def test_policy_unknown_type_emits_generic_setting():
    raw = _policy("sites.service_status", {"serviceState": "ENABLED"})

    obj = GoogleWorkspaceNormalizer().normalize("policy", raw)[0]

    assert obj.kind == "setting"
    assert obj.attributes["key"] == "sites.service_status"
    assert obj.attributes["value"] == {"serviceState": "ENABLED"}


def test_policy_missing_setting_type_emits_nothing():
    raw = _raw("policy", "policies/e3", {"type": "ADMIN", "setting": {"value": {}}})
    assert GoogleWorkspaceNormalizer().normalize("policy", raw) == []


def test_mobile_device_compromised_maps_to_resource_device():
    raw = _raw(
        "mobile_device",
        "device-abc",
        {
            "deviceId": "device-abc",
            "email": ["grace@acme.test"],
            "name": ["Grace's iPhone"],
            "type": "IOS",
            "os": "iOS 17.5",
            "status": "APPROVED",
            "deviceCompromisedStatus": "COMPROMISED",
            "encryptionStatus": "ENCRYPTED",
        },
    )

    obj = GoogleWorkspaceNormalizer().normalize("mobile_device", raw)[0]

    assert obj.kind == "resource"
    assert obj.attributes["resource_type"] == "device"
    assert obj.attributes["management_type"] == "mdm"
    assert obj.attributes["compromised"] is True
    assert obj.attributes["encrypted"] is True
    assert obj.attributes["owner_email"] == "grace@acme.test"
    assert obj.attributes["device_type"] == "IOS"


def test_mobile_device_safe_is_not_compromised():
    raw = _raw(
        "mobile_device",
        "device-xyz",
        {
            "deviceId": "device-xyz",
            "email": ["ada@acme.test"],
            "name": ["Ada's Pixel"],
            "type": "ANDROID",
            "deviceCompromisedStatus": "SAFE",
            "encryptionStatus": "ENCRYPTED",
        },
    )

    obj = GoogleWorkspaceNormalizer().normalize("mobile_device", raw)[0]

    assert obj.attributes["compromised"] is False
    assert obj.attributes["encrypted"] is True


def test_mobile_device_unencrypted_has_encrypted_false():
    raw = _raw(
        "mobile_device",
        "device-byod",
        {
            "email": [],
            "name": [],
            "deviceCompromisedStatus": "SAFE",
            "encryptionStatus": "NOT_ENCRYPTED",
        },
    )

    obj = GoogleWorkspaceNormalizer().normalize("mobile_device", raw)[0]

    assert obj.attributes["encrypted"] is False


def test_chromeos_device_is_always_encrypted():
    raw = _raw(
        "chromeos_device",
        "chromeos-1",
        {
            "deviceId": "chromeos-1",
            "serialNumber": "SN-001",
            "annotatedAssetId": "LAPTOP-001",
            "annotatedUser": "ada@acme.test",
            "osVersion": "119.0.6045.105",
            "status": "ACTIVE",
            "model": "HP Chromebook 11",
        },
    )

    obj = GoogleWorkspaceNormalizer().normalize("chromeos_device", raw)[0]

    assert obj.kind == "resource"
    assert obj.attributes["resource_type"] == "device"
    assert obj.attributes["management_type"] == "chromeos"
    assert obj.attributes["compromised"] is False
    assert obj.attributes["encrypted"] is True
    assert obj.attributes["name"] == "LAPTOP-001"
    assert obj.attributes["owner_email"] == "ada@acme.test"


def test_alert_individual_emits_threat_detected_event():
    raw = _raw(
        "alert",
        "gws-alert:alert-001",
        {
            "alertId": "alert-001",
            "type": "Suspicious login",
            "source": "Google identity",
            "createTime": "2026-09-01T12:00:00Z",
            "metadata": {"severity": "HIGH", "status": "OPEN"},
        },
    )

    objects = GoogleWorkspaceNormalizer().normalize("alert", raw)

    assert len(objects) == 1
    obj = objects[0]
    assert obj.kind == "event"
    assert obj.attributes["action"] == "threat.detected"
    assert obj.attributes["action_category"] == "threat"
    assert obj.attributes["attributes"]["severity"] == "HIGH"
    assert obj.attributes["attributes"]["alert_id"] == "alert-001"


def test_alert_count_summary_emits_alert_count_settings():
    raw = _raw(
        "alert",
        "gws-alert-count:summary",
        {
            "is_count_summary": True,
            "counts": {"HIGH": 2, "MEDIUM": 1, "LOW": 0},
        },
    )

    objects = GoogleWorkspaceNormalizer().normalize("alert", raw)

    assert len(objects) == 3
    keys = {o.attributes["key"] for o in objects}
    assert keys == {"open_alerts_high", "open_alerts_medium", "open_alerts_low"}
    high = next(o for o in objects if o.attributes["key"] == "open_alerts_high")
    assert high.attributes["value"] == 2


def test_inbound_sso_profile_emits_setting():
    raw = _raw(
        "inbound_sso_profile",
        "inboundSamlSsoProfiles/acme-okta",
        {
            "name": "inboundSamlSsoProfiles/acme-okta",
            "displayName": "Acme Okta",
            "idpConfig": {
                "entityId": "http://www.okta.com/exkacme1234567",
                "singleSignOnServiceUri": "https://acme.okta.com/app/google/sso/saml",
            },
        },
    )

    obj = GoogleWorkspaceNormalizer().normalize("inbound_sso_profile", raw)[0]

    assert obj.kind == "setting"
    assert "inboundSamlSsoProfiles" in obj.attributes["key"]
    assert obj.attributes["value"]["idpEntityId"] == "http://www.okta.com/exkacme1234567"


def test_inbound_sso_assignment_ou_scoped_has_subject():
    raw = _raw(
        "inbound_sso_assignment",
        "inboundSsoAssignments/eng-saml",
        {
            "name": "inboundSsoAssignments/eng-saml",
            "ssoMode": "SAML_SSO",
            "targetOrgUnit": "orgUnits/id:ou-eng",
            "samlSsoInfo": {"inboundSamlSsoProfile": "inboundSamlSsoProfiles/acme-okta"},
        },
    )

    obj = GoogleWorkspaceNormalizer().normalize("inbound_sso_assignment", raw)[0]

    assert obj.kind == "setting"
    assert obj.attributes["subject_type"] == "group"
    assert obj.attributes["subject_ref"] == "id:ou-eng"
    assert obj.attributes["value"]["ssoMode"] == "SAML_SSO"
    assert obj.relationships[0].target_ref == "id:ou-eng"


def test_admin_activity_grant_admin_privilege_emits_privilege_grant_event():
    raw = _raw(
        "admin_activity",
        "admin:2001",
        {
            "id": {"time": "2026-09-01T08:00:00.000Z", "uniqueQualifier": "2001"},
            "actor": {"email": "ada@acme.test", "profileId": "1"},
            "ipAddress": "203.0.113.1",
            "events": [
                {
                    "name": "GRANT_ADMIN_PRIVILEGE",
                    "parameters": [
                        {"name": "USER_EMAIL", "value": "grace@acme.test"},
                        {"name": "ROLE_NAME", "value": "Help Desk Admin"},
                    ],
                }
            ],
        },
    )

    objects = GoogleWorkspaceNormalizer().normalize("admin_activity", raw)

    assert len(objects) == 1
    obj = objects[0]
    assert obj.kind == "event"
    assert obj.attributes["action"] == "privilege.grant"
    assert obj.attributes["action_category"] == "privilege"
    assert obj.attributes["actor_email"] == "ada@acme.test"
    assert obj.attributes["target_email"] == "grace@acme.test"
    assert obj.attributes["attributes"]["gws_event_name"] == "GRANT_ADMIN_PRIVILEGE"
    assert obj.attributes["attributes"]["ROLE_NAME"] == "Help Desk Admin"


def test_admin_activity_unknown_event_is_dropped():
    raw = _raw(
        "admin_activity",
        "admin:9999",
        {
            "id": {"time": "2026-09-01T09:00:00.000Z"},
            "actor": {"email": "ada@acme.test"},
            "events": [{"name": "SOME_UNDOCUMENTED_EVENT", "parameters": []}],
        },
    )

    assert GoogleWorkspaceNormalizer().normalize("admin_activity", raw) == []


def test_dwd_client_sensitive_scopes_flagged():
    raw = _raw(
        "dwd_client",
        "dwd-client-123456",
        {
            "client_id": "dwd-client-123456",
            "scopes": [
                "https://www.googleapis.com/auth/admin.directory.user",
                "https://www.googleapis.com/auth/gmail.readonly",
            ],
            "revoked": False,
            "last_changed_by": "ada@acme.test",
        },
    )

    objects = GoogleWorkspaceNormalizer().normalize("dwd_client", raw)

    app = objects[0]
    assert app.kind == "oauth_application"
    assert app.attributes["dwd_client"] is True
    assert app.attributes["has_sensitive_scopes"] is True
    assert app.attributes["revoked"] is False
    scope_names = {o.attributes["scope_name"] for o in objects[1:]}
    assert "https://www.googleapis.com/auth/admin.directory.user" in scope_names


def test_dwd_client_non_sensitive_scopes_not_flagged():
    raw = _raw(
        "dwd_client",
        "dwd-safe",
        {
            "client_id": "dwd-safe",
            "scopes": ["openid", "https://www.googleapis.com/auth/userinfo.email"],
            "revoked": False,
        },
    )

    app = GoogleWorkspaceNormalizer().normalize("dwd_client", raw)[0]

    assert app.attributes["has_sensitive_scopes"] is False


def test_is_sensitive_dwd_scope_gmail_is_sensitive():
    from kestrel_connector_google_workspace.normalizer import is_sensitive_dwd_scope

    assert is_sensitive_dwd_scope("https://www.googleapis.com/auth/gmail.readonly") is True
    assert is_sensitive_dwd_scope("https://www.googleapis.com/auth/admin.directory.user") is True
    assert is_sensitive_dwd_scope("openid") is False
    assert is_sensitive_dwd_scope("") is False
