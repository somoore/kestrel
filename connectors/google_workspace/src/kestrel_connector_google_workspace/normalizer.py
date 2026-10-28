# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Maps Google Workspace RawObjects into Kestrel NormalizedObjects.

Entity references use provider ids in `_ref` attributes and in
NormalizedRelationship.source_ref/target_ref; resolution to real foreign keys
happens in the upsert/graph-writer layer once every object in the run has
been normalized.

Two shape differences from GitHub are worth noting, since this connector
exists partly to prove the SDK generalizes:

1. Workspace has *first-class admin roles* (Super Admin, Help Desk Admin,
   custom roles) assigned via roleAssignments. Those become `grant` objects
   carrying a `role_ref` -- a path GitHub never exercises, because GitHub's
   grants are always resource access and its one "role" is synthesized by
   the connector itself.
2. A shared-drive permission can be granted to a *group* rather than a user,
   so a single grant kind has to express both direct and group-inherited
   access to the same resource.

Domain payloads emit tenant `setting` rows for workspace-level
security/sharing configuration. The ApplicationInstance is still created
when the connector instance is configured, not by the connector.

v0.2 adds: Cloud Identity Policy API (OU-scoped settings), mobile/ChromeOS
devices as resource:device, Alert Center alerts as events + alert_count_setting,
inbound SAML SSO profiles/assignments, admin/drive/saml Reports event feeds,
customer info settings, and synthetic dwd_client oauth_application objects.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kestrel.connectors.activity_actions import category_for
from kestrel.connectors.sdk.base import NormalizedObject, NormalizedRelationship, RawObject
from kestrel.connectors.sdk.payload import sub_dict
from kestrel.connectors.settings_emit import alert_count_setting, setting_object, settings_from_mapping

# Drive roles, most to least privileged. `organizer` and `fileOrganizer` can
# restructure or delete drive content, so both map to Kestrel's "admin".
_DRIVE_ROLE_TO_PERMISSION_LEVEL = {
    "organizer": "admin",
    "fileOrganizer": "admin",
    "writer": "write",
    "commenter": "read",
    "reader": "read",
}

# Only what Admin SDK Directory `domains.get` actually returns: kind, etag,
# domainName, isPrimary, verified, creationTime, domainAliases. Workspace
# *configuration* (2SV enforcement, Drive sharing, Calendar sharing) is not on
# this resource and is not reachable from the Directory API at all -- it lives
# in the Cloud Identity Policy API. Emitting it here produced setting rows that
# only ever existed in fixtures.
_DOMAIN_SETTING_SPECS: list[tuple[str, str, str, str, str | None]] = [
    (
        "is_primary",
        "domain",
        "Primary domain",
        "boolean",
        "Whether this is the primary Google Workspace domain.",
    ),
    (
        "verified",
        "domain",
        "Domain verified",
        "boolean",
        "Whether Google has verified ownership of the domain.",
    ),
]

# Groups Settings API keys worth a posture row. Google returns every value as
# a string ("true" / "ALL_IN_DOMAIN_CAN_JOIN"); booleans are coerced below.
_GROUP_SETTING_SPECS: list[tuple[str, str, str, str, str, str | None]] = [
    (
        "allowExternalMembers",
        "group_allow_external_members",
        "sharing",
        "Allows external members",
        "boolean",
        "Whether people outside the Workspace domains may be members of this group.",
    ),
    (
        "whoCanJoin",
        "group_who_can_join",
        "access",
        "Who can join",
        "string",
        "Who may join the group without an owner adding them.",
    ),
    (
        "whoCanPostMessage",
        "group_who_can_post_message",
        "sharing",
        "Who can post",
        "string",
        "Who may send mail to the group address (ANYONE_CAN_POST accepts mail from the internet).",
    ),
    (
        "whoCanViewMembership",
        "group_who_can_view_membership",
        "access",
        "Who can view membership",
        "string",
        "Who may list the members of this group.",
    ),
]

# OAuth scopes that read or write user data broadly. A third-party app holding
# any of these is the "risky OAuth application" every Workspace review starts
# with. Matched by substring against the scope URL.
_SENSITIVE_SCOPE_MARKERS: tuple[str, ...] = (
    "mail.google.com",
    "/auth/gmail",
    "/auth/drive",
    "/auth/admin.",
    "/auth/cloud-platform",
    "/auth/contacts",
    "/auth/spreadsheets",
    "/auth/documents",
    "/auth/calendar",
)
# Narrow Drive scopes that only touch files the app created or the user picked.
_BENIGN_SCOPE_SUFFIXES: tuple[str, ...] = ("/auth/drive.file", "/auth/drive.appdata", "/auth/drive.install")
_GOOGLE_PUBLISHER_MARKERS: tuple[str, ...] = ("google", "gsuite", "workspace")

# DWD scopes that grant tenant-wide admin or read-all access.
_DWD_SENSITIVE_SCOPE_MARKERS: tuple[str, ...] = (
    "/auth/admin.",
    "/auth/cloud-platform",
    "/auth/gmail",
    "/auth/drive",
    "/auth/contacts",
    "/auth/calendar",
    "/auth/spreadsheets",
    "/auth/documents",
)


def is_sensitive_google_scope(scope: str) -> bool:
    text = (scope or "").strip().lower()
    if not text:
        return False
    if any(text.endswith(suffix) for suffix in _BENIGN_SCOPE_SUFFIXES):
        return False
    return any(marker in text for marker in _SENSITIVE_SCOPE_MARKERS)


def is_sensitive_dwd_scope(scope: str) -> bool:
    """Broader check for DWD clients: any scope that grants tenant-wide data access."""
    text = (scope or "").strip().lower()
    return bool(text) and any(marker in text for marker in _DWD_SENSITIVE_SCOPE_MARKERS)


# Reports `login` event names worth an ActivityEvent. Successful sign-ins are
# deliberately absent: at directory scale they are noise, and `lastLoginTime`
# on the user already carries the activity signal.
_LOGIN_EVENT_TO_KESTREL: dict[str, str] = {
    "login_failure": "auth.failure",
    "suspicious_login": "threat.detected",
    "suspicious_login_less_secure_app": "threat.detected",
    "suspicious_programmatic_login": "threat.detected",
    "account_disabled_password_leak": "threat.detected",
    "account_disabled_hijacked": "threat.detected",
    "account_disabled_spamming": "threat.detected",
    "gov_attack_warning": "threat.detected",
    "2sv_disable": "mfa.disable",
    "password_edit": "credential.change",
    "recovery_email_edit": "credential.change",
    "recovery_phone_edit": "credential.change",
}

# Admin Reports `admin` application event names → normalized actions.
_ADMIN_EVENT_TO_KESTREL: dict[str, str] = {
    # Privilege changes
    "GRANT_ADMIN_PRIVILEGE": "privilege.grant",
    "REVOKE_ADMIN_PRIVILEGE": "privilege.revoke",
    "ASSIGN_ROLE": "privilege.grant",
    "UNASSIGN_ROLE": "privilege.revoke",
    "CREATE_ROLE": "config.change",
    "DELETE_ROLE": "config.change",
    "UPDATE_ROLE": "config.change",
    # DWD client access
    "AUTHORIZE_API_CLIENT_ACCESS": "token.grant",
    "REVOKE_API_CLIENT_ACCESS": "oauth.app.revoke",
    # SSO configuration
    "CHANGE_SSO_SETTINGS": "sso.change",
    "CHANGE_APPLICATION_SETTING": "config.change",
    "TOGGLE_SERVICE_ENABLED": "config.change",
    # Account management
    "CREATE_USER": "identity.add",
    "SUSPEND_USER": "identity.deactivate",
    "DELETE_USER": "identity.deactivate",
    "UNSUSPEND_USER": "dormant.reactivate",
    "RENAME_USER": "config.change",
    # Password / 2SV admin actions
    "CHANGE_PASSWORD": "credential.change",
    "RESET_SIGNIN_COOKIES": "session.reset",
    # Data export
    "REQUEST_GOOGLE_USER_DATA_EXPORT": "data.export",
    "COMPLETE_USER_DATA_EXPORT": "data.export",
}

# Admin Reports `drive` application event names → normalized actions.
_DRIVE_EVENT_TO_KESTREL: dict[str, str] = {
    "change_document_access_scope": "sharing.external",
    "change_document_visibility": "sharing.external",
    "change_user_access": "sharing.external",
    "change_acl_editors": "sharing.external",
    "add_to_folder": "access.grant",
    "remove_from_folder": "access.revoke",
    "download": "data.export",
    "upload": "config.change",
    "delete": "config.change",
}

# Admin Reports `saml` application event names → normalized actions.
_SAML_EVENT_TO_KESTREL: dict[str, str] = {
    "login_success": "auth.success",
    "login_failure": "auth.failure",
    "logout": "auth.success",
    "setup": "sso.change",
}

# Admin Reports `user_accounts` application event names → normalized actions.
_USER_ACCOUNTS_EVENT_TO_KESTREL: dict[str, str] = {
    "password_edit": "credential.change",
    "2sv_enroll": "mfa.enable",
    "2sv_disable": "mfa.disable",
    "recovery_email_edit": "credential.change",
    "recovery_phone_edit": "credential.change",
    "account_disabled_password_leak": "threat.detected",
}

# Admin Reports `groups` application event names → normalized actions.
_GROUPS_EVENT_TO_KESTREL: dict[str, str] = {
    "add_member": "group.member.add",
    "remove_member": "group.member.remove",
    "join": "group.member.add",
    "leave": "group.member.remove",
    "create_group": "config.change",
    "delete_group": "config.change",
    "change_group_setting": "config.change",
    "add_info_object": "config.change",
}

# Admin Reports `mobile` application event names → normalized actions.
_MOBILE_EVENT_TO_KESTREL: dict[str, str] = {
    "DEVICE_REGISTER_UNREGISTER_EVENT": "device.enroll",
    "DEVICE_SYNC_EVENT": "device.enroll",
    "SUSPICIOUS_ACTIVITY_EVENT": "device.compromise",
    "REMOTE_WIPE_EVENT": "device.wipe",
    "DEVICE_COMPROMISED_EVENT": "device.compromise",
    "FAILED_PASSWORD_ATTEMPTS_EVENT": "auth.failure",
    "ACCOUNT_WIPE_EVENT": "device.wipe",
}


# Map fixture / Admin SDK aliases onto canonical setting keys.
_DOMAIN_PAYLOAD_ALIASES: dict[str, tuple[str, ...]] = {
    "is_primary": ("is_primary", "isPrimary"),
    "verified": ("verified",),
}

# Cloud Identity Policy API setting type -> (setting_key, category, label, description).
# Keys are `setting.type` as the API returns it, minus the `settings/` prefix
# (`settings/security.password` -> `security.password`). The full list is at
# https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings
# and the field names below are the ones the API returns. `value` is always the
# raw `setting.value` dict (value_type="object") so policy functions read the
# provider's own field names.
_POLICY_TYPE_TO_SPEC: dict[str, tuple[str, str, str, str | None]] = {
    "security.two_step_verification_enforcement": (
        "security.two_step_verification_enforcement",
        "security",
        "2-Step Verification enforcement",
        "enforcedFrom: RFC 3339 time from which 2-Step Verification is enforced. "
        "The Unix epoch (1970-01-01T00:00:00Z) means enforcement is off; a future time means it is scheduled.",
    ),
    "security.two_step_verification_enrollment": (
        "security.two_step_verification_enrollment",
        "security",
        "2-Step Verification enrollment",
        "allowEnrollment: whether users may enroll in 2-Step Verification.",
    ),
    "security.two_step_verification_grace_period": (
        "security.two_step_verification_grace_period",
        "security",
        "2-Step Verification enrollment period",
        'enrollmentGracePeriod: how long a new user has to enroll, as a duration ("604800s").',
    ),
    "security.two_step_verification_device_trust": (
        "security.two_step_verification_device_trust",
        "security",
        "2-Step Verification device trust",
        "allowTrustingDevice: whether users may skip the second step on a device they trust.",
    ),
    "security.two_step_verification_enforcement_factor": (
        "security.two_step_verification_enforcement_factor",
        "security",
        "2-Step Verification methods",
        "allowedSignInFactorSet: ALL | PASSKEY_ONLY | PASSKEY_PLUS_SECURITY_CODE | "
        "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE | NO_TELEPHONY.",
    ),
    "security.less_secure_apps": (
        "security.less_secure_apps",
        "security",
        "Less secure app access",
        "allowLessSecureApps: true means apps that use basic authentication may sign in.",
    ),
    "security.password": (
        "security.password",
        "security",
        "Password management",
        "allowedStrength: STRONG | WEAK; minimumLength; maximumLength; enforceRequirementsAtLogin; "
        'allowReuse; expirationDuration as a duration ("0s" never expires).',
    ),
    "security.session_controls": (
        "security.session_controls",
        "security",
        "Google session control",
        'webSessionDuration: web session length as a duration ("43200s").',
    ),
    "security.super_admin_account_recovery": (
        "security.super_admin_account_recovery",
        "security",
        "Super admin account recovery",
        "enableAccountRecovery: whether super admins can recover their own account.",
    ),
    "security.user_account_recovery": (
        "security.user_account_recovery",
        "security",
        "User account recovery",
        "enableAccountRecovery: whether users and non-super admins can recover their own account.",
    ),
    "gmail.auto_forwarding": (
        "gmail.auto_forwarding",
        "sharing",
        "Gmail automatic forwarding",
        "enableAutoForwarding: true means users may forward incoming mail to another address automatically.",
    ),
    "gmail.imap_access": (
        "gmail.imap_access",
        "access",
        "Gmail IMAP access",
        "enableImapAccess: true means IMAP is allowed.",
    ),
    "gmail.pop_access": (
        "gmail.pop_access",
        "access",
        "Gmail POP access",
        "enablePopAccess: true means POP is allowed.",
    ),
    "drive_and_docs.external_sharing": (
        "drive_and_docs.external_sharing",
        "sharing",
        "Drive external sharing",
        "externalSharingMode: DISALLOWED | ALLOWLISTED_DOMAINS | ALLOWED, plus the related "
        "allowNonGoogleInvites, allowPublishingFiles, allowReceivingExternalFiles and warning flags.",
    ),
    "drive_and_docs.general_access_default": (
        "drive_and_docs.general_access_default",
        "sharing",
        "Drive default access for new files",
        "defaultFileAccess: who can open a newly created file before it is shared.",
    ),
    "workspace_marketplace.apps_access_options": (
        "workspace_marketplace.apps_access_options",
        "access",
        "Marketplace app access",
        "accessLevel: ALLOW_ALL | ALLOW_LISTED_APPS | ALLOW_NONE; allowAllInternalApps.",
    ),
    "workspace_marketplace.apps_allowlist": (
        "workspace_marketplace.apps_allowlist",
        "access",
        "Marketplace allowlisted apps",
        "The allowlisted Marketplace applications and whether each is ALLOWED or BLOCKED.",
    ),
    "takeout.service_status": (
        "takeout.service_status",
        "access",
        "Google Takeout service status",
        "serviceState: ENABLED | DISABLED for the organizational unit.",
    ),
}


def _org_unit_ref(value: Any) -> str:
    """Policy API `policyQuery.orgUnit` (`orgUnits/<id>`) as the Directory API's
    `orgUnitId` (`id:<id>`), which is the provider id of the `org_unit` row."""
    text = str(value or "").removeprefix("orgUnits/")
    if not text or text.startswith("id:"):
        return text
    return f"id:{text}"


def _permission_level(drive_role: str) -> str:
    return _DRIVE_ROLE_TO_PERMISSION_LEVEL.get(drive_role, "read")


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _last_login(value: Any) -> datetime | None:
    parsed = _parse_dt(value)
    if parsed is None or parsed.year <= 1970:
        return None
    return parsed


# Admin SDK privilege names that let a role change who can sign in, what they
# can reach, or the security configuration itself. A custom role holding any of
# these is privileged whatever it is called.
_PRIVILEGED_PRIVILEGE_NAMES = frozenset(
    {
        "SUPER_ADMIN",
        "ADMIN_PRIVILEGES",
        "ROLE_MANAGEMENT",
        "SECURITY_SETTINGS",
        "USERS_ALL",
        "USERS_CREATE",
        "USERS_UPDATE",
        "USERS_DELETE",
        "USERS_RESET_PASSWORD",
        "USER_SECURITY_ALL",
        "GROUPS_ALL",
        "GROUPS_CREATE",
        "GROUPS_UPDATE",
        "GROUPS_DELETE",
        "ORGANIZATION_UNITS_ALL",
        "ORGANIZATION_UNITS_UPDATE",
        "SERVICE_DATA_TRANSFER",
        "APP_ADMIN",
        "DOMAIN_MANAGEMENT",
    }
)


def _privilege_names(role: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for row in role.get("rolePrivileges") or []:
        if isinstance(row, dict) and row.get("privilegeName"):
            names.append(str(row["privilegeName"]))
    return sorted(set(names))


def _is_privileged_role(role: dict[str, Any]) -> bool:
    """Super Admin is unambiguously privileged; any other role is privileged
    when its `rolePrivileges` include a privilege that can change identities,
    groups, org units, or security settings. Roles listed without privileges
    (a credential that can list roles but not read privileges) fall back to
    the Super Admin flag alone."""
    if role.get("isSuperAdminRole"):
        return True
    return any(name in _PRIVILEGED_PRIVILEGE_NAMES for name in _privilege_names(role))


def _role_name(role: dict[str, Any]) -> str:
    """Built-in roles carry a token in `roleName` ("_SEED_ADMIN_ROLE") and
    the human label in `roleDescription` ("Super Admin"). Custom roles are
    the other way round: `roleName` is what the admin typed, and
    `roleDescription` is prose about it. Preferring the description
    unconditionally would rename "Groups Reader" to "Custom read-only role
    for group metadata".
    """
    role_name = role.get("roleName") or ""
    if role_name.startswith("_"):
        return role.get("roleDescription") or role_name
    return role_name or role.get("roleDescription") or str(role["roleId"])


def _user_setting(
    payload: dict[str, Any],
    *,
    provider_id: str,
    key: str,
    category: str,
    label: str,
    value: Any,
    value_type: str,
    description: str | None = None,
) -> NormalizedObject:
    """A setting scoped to one identity, not to the tenant.

    Mirrors the per-repository pattern in the GitHub connector: the row carries
    `subject_type`/`subject_ref` so the upsert resolves it to the identity, and
    an `applies_to` edge so the graph shows what the setting governs.
    """
    obj = setting_object(
        key=key,
        category=category,
        label=label,
        value=value,
        value_type=value_type,
        description=description,
        raw_source=payload,
        provider_id_prefix=f"user-setting:{provider_id}",
    )
    obj.attributes["subject_type"] = "identity"
    obj.attributes["subject_ref"] = provider_id
    obj.relationships = [
        NormalizedRelationship(
            edge_type="applies_to",
            source_ref=obj.provider_id,
            target_ref=provider_id,
        )
    ]
    return obj


def _display_name(user: dict[str, Any]) -> str:
    name = user.get("name") or {}
    return name.get("fullName") or user.get("primaryEmail") or str(user["id"])


def _activity_event_objects(
    raw: RawObject,
    event_map: dict[str, str],
    *,
    app_label: str,
) -> list[NormalizedObject]:
    """Generic Reports activity → NormalizedObject list for event-type feeds.

    Maps each curated event name to a normalized action; unknown events are
    dropped. The actor email and target (when present as a parameter) are
    carried through to support identity correlation.
    """
    payload = raw.payload
    ident = sub_dict(payload, "id")
    actor = sub_dict(payload, "actor")
    occurred_at = ident.get("time")
    actor_email = actor.get("email")
    actor_id = actor.get("profileId")
    objects: list[NormalizedObject] = []

    for index, event in enumerate(payload.get("events") or []):
        if not isinstance(event, dict):
            continue
        name = str(event.get("name") or "")
        action = event_map.get(name)
        if action is None:
            continue
        params = {
            str(p.get("name")): (p.get("value") if "value" in p else p.get("multiValue") or p.get("boolValue"))
            for p in (event.get("parameters") or [])
            if isinstance(p, dict) and p.get("name")
        }
        target_email = params.get("USER_EMAIL") or params.get("user_email") or params.get("TARGET_USER_EMAIL")
        objects.append(
            NormalizedObject(
                kind="event",
                provider_id=f"{raw.provider_id}:{index}" if index else raw.provider_id,
                attributes={
                    "action": action,
                    "action_category": category_for(action),
                    "actor_email": actor_email,
                    "actor_provider_id": str(actor_id) if actor_id else None,
                    "target_email": target_email,
                    "target_type": "identity" if target_email else None,
                    "occurred_at": occurred_at,
                    "summary": f"Google Workspace {app_label}: {name} ({action})",
                    "attributes": {
                        "gws_event_name": name,
                        "app": app_label,
                        "ip_address": payload.get("ipAddress"),
                        **{k: v for k, v in params.items() if k not in {"USER_EMAIL", "user_email"}},
                    },
                },
                raw_source=payload,
            )
        )
    return objects


class GoogleWorkspaceNormalizer:
    def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]:
        method = getattr(self, f"_normalize_{object_type}", None)
        if method is None:
            raise ValueError(f"GoogleWorkspaceNormalizer does not support object_type '{object_type}'")
        return method(raw)

    def _normalize_domain(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        normalized: dict[str, Any] = {}
        for key, aliases in _DOMAIN_PAYLOAD_ALIASES.items():
            for alias in aliases:
                if alias in payload:
                    normalized[key] = payload[alias]
                    break
        return settings_from_mapping(normalized, _DOMAIN_SETTING_SPECS, provider_id_prefix="org-setting")

    def _normalize_user(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        return [
            NormalizedObject(
                kind="identity",
                provider_id=raw.provider_id,
                attributes={
                    "identity_type": "user",
                    "display_name": _display_name(payload),
                    "email": payload.get("primaryEmail"),
                    # Suspended and archived both mean the account cannot be
                    # used; Kestrel models that as a single disabled flag.
                    "is_disabled": bool(payload.get("suspended") or payload.get("archived")),
                    "is_external": False,
                    "mfa_enabled": bool(payload.get("isEnrolledIn2Sv")),
                    # Google reports 1970-01-01 for never-signed-in accounts.
                    "last_active_at": _last_login(payload.get("lastLoginTime")),
                    "last_active_source": "login" if _last_login(payload.get("lastLoginTime")) else None,
                    "created_at_source": _parse_dt(payload.get("creationTime")),
                    # Extra context for the graph node and identity detail. The
                    # flags are what the directory says about admin standing even
                    # when the role-management API is gated for this credential.
                    "org_unit_path": payload.get("orgUnitPath"),
                    "is_admin": bool(payload.get("isAdmin")),
                    "is_delegated_admin": bool(payload.get("isDelegatedAdmin")),
                    "is_enforced_in_2sv": bool(payload.get("isEnforcedIn2Sv")),
                },
                raw_source=payload,
                relationships=(
                    [
                        NormalizedRelationship(
                            edge_type="member_of",
                            source_ref=raw.provider_id,
                            target_ref=str(payload["org_unit_id"]),
                            access_path="direct",
                            properties={"kind": "org_unit"},
                        )
                    ]
                    if payload.get("org_unit_id")
                    else []
                ),
            ),
            # 2-Step Verification *enforcement* is per user, not per domain:
            # `isEnforcedIn2Sv` is a field on the Directory users resource, and
            # there is no domain-level equivalent anywhere in the Directory API.
            # Subject-scoped to the identity so a finding names the account that
            # is not enforced rather than asserting a tenant-wide flag Google
            # never returned.
            _user_setting(
                payload,
                provider_id=raw.provider_id,
                key="two_step_verification_enforced",
                category="security",
                label="2-Step Verification enforced",
                value=bool(payload.get("isEnforcedIn2Sv")),
                value_type="boolean",
                description=(
                    "Whether the administrator enforces 2-Step Verification on this account. "
                    "Enrollment (`mfa_enabled`) is the user's own state; enforcement is the "
                    "policy applied to them."
                ),
            ),
        ]

    def _normalize_domain_list(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        name = str(payload.get("domainName") or raw.provider_id)
        aliases = [str((a or {}).get("domainAliasName") or "") for a in payload.get("domainAliases") or []]
        return [
            setting_object(
                key=f"domain_verified:{name}",
                category="domain",
                label=f"Domain verified ({name})",
                value=bool(payload.get("verified")),
                value_type="boolean",
                description="Whether Google has verified ownership of this domain. Unverified domains cannot "
                "receive mail and their aliases are not enforced.",
                raw_source=payload,
                provider_id_prefix=f"domain:{name}",
            ),
            setting_object(
                key=f"domain_aliases:{name}",
                category="domain",
                label=f"Domain aliases ({name})",
                value=[a for a in aliases if a],
                value_type="object",
                description="Alias domains that deliver to this domain; addresses on them are internal.",
                raw_source=payload,
                provider_id_prefix=f"domain:{name}",
            ),
        ]

    def _normalize_org_unit(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        path = str(payload.get("orgUnitPath") or "/")
        parent = payload.get("parentOrgUnitId")
        relationships = []
        if parent:
            relationships.append(
                NormalizedRelationship(
                    edge_type="member_of",
                    source_ref=raw.provider_id,
                    target_ref=str(parent),
                    access_path="direct",
                    properties={"kind": "org_unit"},
                )
            )
        return [
            NormalizedObject(
                kind="group",
                provider_id=raw.provider_id,
                attributes={
                    "name": path,
                    "description": payload.get("description") or f"Organizational unit {path}",
                    "kind": "org_unit",
                    "org_unit_path": path,
                    "block_inheritance": bool(payload.get("blockInheritance")),
                },
                raw_source=payload,
                relationships=relationships,
            )
        ]

    def _normalize_group(self, raw: RawObject) -> list[NormalizedObject]:
        return [self._group_object(raw.provider_id, raw.payload)]

    @staticmethod
    def _group_object(provider_id: str, payload: dict[str, Any], **extra: Any) -> NormalizedObject:
        return NormalizedObject(
            kind="group",
            provider_id=provider_id,
            attributes={"name": payload.get("name") or payload["email"], "description": payload.get("description")},
            raw_source=payload,
            **extra,
        )

    def _normalize_group_setting(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        group_id = str(payload["group_id"])
        label = str(payload.get("group_email") or payload.get("email") or group_id)
        objects: list[NormalizedObject] = []
        for api_key, key, category, title, value_type, description in _GROUP_SETTING_SPECS:
            if api_key not in payload:
                continue
            raw_value = payload[api_key]
            value: Any = raw_value
            if value_type == "boolean":
                value = str(raw_value).strip().lower() == "true" if not isinstance(raw_value, bool) else raw_value
            obj = setting_object(
                key=key,
                category=category,
                label=f"{title} ({label})",
                value=value,
                value_type=value_type,
                description=description,
                raw_source={"key": api_key, "value": raw_value, "group_email": label},
                provider_id_prefix=f"group-setting:{group_id}",
            )
            obj.attributes["subject_type"] = "group"
            obj.attributes["subject_ref"] = group_id
            obj.relationships = [
                NormalizedRelationship(
                    edge_type="applies_to",
                    source_ref=obj.provider_id,
                    target_ref=group_id,
                    access_path="direct",
                )
            ]
            objects.append(obj)
        return objects

    def _normalize_group_member(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        group_id = str(payload["group_id"])
        member_id = str(payload.get("id") or raw.provider_id.rsplit(":", 1)[-1])
        member_type = str(payload.get("type") or "USER").upper()
        email = str(payload.get("email") or "").strip().lower() or None
        is_external = bool(payload.get("is_external"))

        nested = payload.get("nested_group")
        if member_type == "GROUP" and isinstance(nested, dict):
            # Nested group: re-emit the child with a group -> group edge. Same
            # attributes as the `group` family so the upsert sees no churn.
            return [
                self._group_object(
                    member_id,
                    nested,
                    relationships=[
                        NormalizedRelationship(
                            edge_type="member_of",
                            source_ref=member_id,
                            target_ref=group_id,
                            access_path="direct",
                            properties={"membership_role": payload.get("role", "MEMBER"), "nested_group": True},
                        )
                    ],
                )
            ]
        if member_type in {"CUSTOMER", "DOMAIN"}:
            # "Everyone in the domain" has no principal to attach; the group
            # settings row (whoCanJoin) carries that exposure instead.
            return []

        objects: list[NormalizedObject] = []
        if not payload.get("is_directory_user", True):
            # Someone outside the directory (an external address, or a user
            # the delegated admin cannot see). Without an identity row the
            # membership could not be stored, and an external member of an
            # internal group is exactly what a reviewer needs to see.
            objects.append(
                NormalizedObject(
                    kind="identity",
                    provider_id=member_id,
                    attributes={
                        "identity_type": "external_identity",
                        "display_name": email or member_id,
                        "email": email,
                        "is_disabled": str(payload.get("status") or "").upper() == "SUSPENDED",
                        "is_external": True,
                        "mfa_enabled": None,
                        "source_domain": email.rsplit("@", 1)[-1] if email and "@" in email else None,
                        "guest_type": "external_group_member",
                    },
                    raw_source=payload,
                )
            )
        objects.append(
            NormalizedObject(
                kind="group_membership",
                provider_id=raw.provider_id,
                attributes={"group_ref": group_id, "identity_ref": member_id, "is_external": is_external},
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="member_of",
                        source_ref=member_id,
                        target_ref=group_id,
                        access_path="direct",
                        properties={"membership_role": payload.get("role", "MEMBER"), "is_external": is_external},
                    )
                ],
            )
        )
        return objects

    def _normalize_admin_role(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        if payload.get("synthetic_from_user_flag"):
            # Role-management API gated: the directory's isAdmin /
            # isDelegatedAdmin flags are the only admin signal available.
            return [
                NormalizedObject(
                    kind="role",
                    provider_id=raw.provider_id,
                    attributes={
                        "name": str(payload.get("roleDescription") or raw.provider_id),
                        "is_privileged": bool(payload.get("isSuperAdminRole")),
                        "is_super_admin_role": bool(payload.get("isSuperAdminRole")),
                        "is_system_role": True,
                        "is_custom_role": False,
                        "derived_from": "directory_user_flags",
                    },
                    raw_source=payload,
                )
            ]
        is_super_admin = bool(payload.get("isSuperAdminRole"))
        is_system = payload.get("isSystemRole")
        privileges = _privilege_names(payload)
        return [
            NormalizedObject(
                kind="role",
                provider_id=raw.provider_id,
                attributes={
                    "name": _role_name(payload),
                    "is_privileged": _is_privileged_role(payload),
                    "is_super_admin_role": is_super_admin,
                    "is_system_role": bool(is_system),
                    "is_custom_role": is_system is False,
                    "privilege_names": privileges,
                    "privileged_privilege_names": [n for n in privileges if n in _PRIVILEGED_PRIVILEGE_NAMES],
                },
                raw_source=payload,
            )
        ]

    def _normalize_role_assignment(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        role_id = str(payload["roleId"])
        identity_id = str(payload["assignedTo"])
        return [
            NormalizedObject(
                kind="grant",
                provider_id=raw.provider_id,
                attributes={
                    "granted_via": "direct",
                    "identity_ref": identity_id,
                    "role_ref": role_id,
                },
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="assigned_role",
                        source_ref=identity_id,
                        target_ref=role_id,
                        access_path="direct",
                    )
                ],
            )
        ]

    def _normalize_login_activity(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        ident = sub_dict(payload, "id")
        actor = sub_dict(payload, "actor")
        occurred_at = ident.get("time")
        actor_email = actor.get("email")
        actor_id = actor.get("profileId")
        objects: list[NormalizedObject] = []
        for index, event in enumerate(payload.get("events") or []):
            if not isinstance(event, dict):
                continue
            name = str(event.get("name") or "")
            action = _LOGIN_EVENT_TO_KESTREL.get(name)
            if action is None:
                continue
            params = {
                str(p.get("name")): (p.get("value") if "value" in p else p.get("multiValue") or p.get("boolValue"))
                for p in (event.get("parameters") or [])
                if isinstance(p, dict) and p.get("name")
            }
            objects.append(
                NormalizedObject(
                    kind="event",
                    provider_id=f"{raw.provider_id}:{index}" if index else raw.provider_id,
                    attributes={
                        "action": action,
                        "action_category": category_for(action),
                        "actor_email": actor_email,
                        "actor_provider_id": str(actor_id) if actor_id else None,
                        # Login events are about the actor's own account.
                        "target_email": actor_email,
                        "target_type": "identity" if actor_email else None,
                        "target_provider_id": str(actor_id) if actor_id else None,
                        "occurred_at": occurred_at,
                        "summary": f"Google Workspace login: {name} ({action})",
                        "attributes": {
                            "gws_event_name": name,
                            "login_type": params.get("login_type"),
                            "login_failure_type": params.get("login_failure_type"),
                            "is_suspicious": params.get("is_suspicious"),
                            "ip_address": payload.get("ipAddress"),
                        },
                    },
                    raw_source=payload,
                )
            )
        return objects

    def _normalize_user_token(self, raw: RawObject) -> list[NormalizedObject]:
        """A user's consent to an OAuth client: the app, its scopes, the grant."""
        payload = raw.payload
        client_id = str(payload.get("clientId") or "")
        user_id = str(payload["user_id"])
        app_ref = f"oauth-client:{client_id}"
        display = str(payload.get("displayText") or client_id)
        native = bool(payload.get("nativeApp"))
        anonymous = bool(payload.get("anonymous"))
        publisher = "google" if any(m in display.lower() for m in _GOOGLE_PUBLISHER_MARKERS) else "third-party"
        scopes = [str(sc) for sc in (payload.get("scopes") or []) if sc]
        objects: list[NormalizedObject] = [
            NormalizedObject(
                kind="oauth_application",
                provider_id=app_ref,
                attributes={
                    "name": display,
                    "publisher": publisher,
                    # Google marks apps that are not on its verified list as anonymous.
                    "is_verified": (not anonymous) if "anonymous" in payload else None,
                    "owner_identity_ref": None,
                    "client_id": client_id,
                    "native_app": native,
                },
                raw_source={k: v for k, v in payload.items() if k not in {"user_id", "user_email"}},
            )
        ]
        for scope in scopes:
            objects.append(
                NormalizedObject(
                    kind="oauth_scope",
                    provider_id=f"{app_ref}:{scope}",
                    attributes={
                        "oauth_application_ref": app_ref,
                        "scope_name": scope,
                        "is_sensitive": is_sensitive_google_scope(scope),
                    },
                    raw_source={"clientId": client_id, "scope": scope},
                )
            )
        objects.append(
            NormalizedObject(
                kind="oauth_grant",
                provider_id=raw.provider_id,
                attributes={
                    "oauth_application_ref": app_ref,
                    "identity_ref": user_id,
                    # Directory tokens carry no timestamps.
                    "granted_at": None,
                    "last_used_at": None,
                },
                raw_source=payload,
                relationships=[
                    NormalizedRelationship(
                        edge_type="possesses_scope",
                        source_ref=user_id,
                        target_ref=app_ref,
                        access_path="oauth_derived",
                        properties={"scope_count": len(scopes), "sensitive": any(map(is_sensitive_google_scope, scopes))},
                    )
                ],
            )
        )
        return objects

    def _normalize_shared_drive(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        return [
            NormalizedObject(
                kind="resource",
                provider_id=raw.provider_id,
                attributes={
                    "name": payload["name"],
                    "resource_type": "shared_drive",
                    # Shared drives are not public objects; "anyone"
                    # permissions are represented on the grant instead.
                    "visibility": "private",
                },
                raw_source=payload,
            )
        ]

    def _normalize_drive_permission(self, raw: RawObject) -> list[NormalizedObject]:
        payload = raw.payload
        drive_id = str(payload["drive_id"])
        permission_level = _permission_level(payload.get("role", "reader"))
        grantee_type = payload.get("type")

        # An "anyone" (link-sharing) permission has no principal to attach a
        # grant to. Dropping it silently would hide exactly the kind of
        # exposure this product exists to surface, so it becomes a grant with
        # no identity/group ref, flagged in its attributes for policies to
        # match on.
        if grantee_type == "anyone":
            return [
                NormalizedObject(
                    kind="grant",
                    provider_id=raw.provider_id,
                    attributes={
                        "granted_via": "direct",
                        "resource_ref": drive_id,
                        "permission_level": permission_level,
                        "is_public_link": True,
                    },
                    raw_source=payload,
                )
            ]

        if grantee_type == "group" and payload.get("resolved_group_id"):
            group_id = str(payload["resolved_group_id"])
            return [
                NormalizedObject(
                    kind="grant",
                    provider_id=raw.provider_id,
                    attributes={
                        "granted_via": "group",
                        "resource_ref": drive_id,
                        "source_group_ref": group_id,
                        "permission_level": permission_level,
                    },
                    raw_source=payload,
                    relationships=[
                        NormalizedRelationship(
                            edge_type="can_access",
                            source_ref=group_id,
                            target_ref=drive_id,
                            access_path="inherited_group",
                            properties={"permission_level": permission_level},
                        )
                    ],
                )
            ]

        if grantee_type == "user" and payload.get("resolved_user_id"):
            identity_id = str(payload["resolved_user_id"])
            return [
                NormalizedObject(
                    kind="grant",
                    provider_id=raw.provider_id,
                    attributes={
                        "granted_via": "direct",
                        "resource_ref": drive_id,
                        "identity_ref": identity_id,
                        "permission_level": permission_level,
                    },
                    raw_source=payload,
                    relationships=[
                        NormalizedRelationship(
                            edge_type="can_access",
                            source_ref=identity_id,
                            target_ref=drive_id,
                            access_path="direct",
                            properties={"permission_level": permission_level},
                        )
                    ],
                )
            ]

        # A grantee outside the directory (an external user, or a domain
        # grant). Kept as an unattributed grant rather than dropped, for the
        # same reason as public links.
        return [
            NormalizedObject(
                kind="grant",
                provider_id=raw.provider_id,
                attributes={
                    "granted_via": "direct",
                    "resource_ref": drive_id,
                    "permission_level": permission_level,
                    "external_grantee": payload.get("emailAddress"),
                },
                raw_source=payload,
            )
        ]

    # -------------------------------------------------------------------------
    # v0.2 normalizers
    # -------------------------------------------------------------------------

    def _normalize_customer(self, raw: RawObject) -> list[NormalizedObject]:
        """Directory customer: ID and creation time as tenant-level settings."""
        payload = raw.payload
        objects: list[NormalizedObject] = []
        if payload.get("id"):
            objects.append(
                setting_object(
                    key="customer_id",
                    category="domain",
                    label="Customer ID",
                    value=str(payload["id"]),
                    value_type="string",
                    description="Google Workspace customer ID (e.g. C01234abc).",
                    raw_source=payload,
                    provider_id_prefix="org-setting",
                )
            )
        if payload.get("customerCreationTime"):
            objects.append(
                setting_object(
                    key="customer_creation_time",
                    category="domain",
                    label="Workspace tenant created",
                    value=str(payload["customerCreationTime"]),
                    value_type="string",
                    description="When the Google Workspace account was created.",
                    raw_source=payload,
                    provider_id_prefix="org-setting",
                )
            )
        return objects

    def _normalize_policy(self, raw: RawObject) -> list[NormalizedObject]:
        """Cloud Identity Policy API policy -> subject-scoped setting.

        The payload is a `Policy` resource. `setting.type` names the setting
        (`settings/security.password`) and `setting.value` holds its fields.
        `policyQuery.orgUnit` (`orgUnits/<id>`) is the organizational unit the
        policy applies to, and `policyQuery.group` (`groups/<id>`) is set when
        it applies to a group inside that unit. The top-level `type` is
        `ADMIN` or `SYSTEM`, not the setting name. Every policy names an
        organizational unit, so a customer-wide setting is the root unit's.

        Each policy maps to one setting row whose `value` is the raw
        `setting.value` dict (value_type=object), so policy functions read the
        provider's own field names. The row carries `subject_type=group` and
        the unit or group as `subject_ref`, so a finding names where the
        setting applies.
        """
        payload = raw.payload
        setting = payload.get("setting") or {}
        setting_type = str(setting.get("type") or "").removeprefix("settings/")
        if not setting_type:
            return []
        spec = _POLICY_TYPE_TO_SPEC.get(setting_type)
        if spec is None:
            # Unknown setting type: emit a generic setting so it is visible in the graph.
            key = setting_type
            category = "access"
            label = setting_type
            description = f"Cloud Identity Policy API setting {setting_type!r}."
        else:
            key, category, label, raw_description = spec
            description = raw_description or ""

        setting_value = setting.get("value") or {}
        query = payload.get("policyQuery") or {}
        ou_id = _org_unit_ref(query.get("orgUnit"))
        group_id = str(query.get("group") or "").removeprefix("groups/")
        scope_ref = group_id or ou_id

        if scope_ref:
            provider_id_prefix = f"policy:{scope_ref}"
            subject_type: str | None = "group"
            subject_ref: str | None = scope_ref
            scope_label = f"group:{group_id}" if group_id else f"OU:{ou_id}"
        else:
            provider_id_prefix = "policy:tenant"
            subject_type = None
            subject_ref = None
            scope_label = "tenant"

        obj = setting_object(
            key=key,
            category=category,
            label=f"{label} ({scope_label})",
            value=setting_value,
            value_type="object",
            description=description,
            raw_source=payload,
            provider_id_prefix=provider_id_prefix,
            subject_type=subject_type,
            subject_ref=subject_ref,
        )
        if scope_ref:
            obj.relationships = [
                NormalizedRelationship(
                    edge_type="applies_to",
                    source_ref=obj.provider_id,
                    target_ref=scope_ref,
                )
            ]
        return [obj]

    def _normalize_mobile_device(self, raw: RawObject) -> list[NormalizedObject]:
        """Mobile device (MDM) → resource:device."""
        payload = raw.payload
        device_id = raw.provider_id
        emails = payload.get("email") or []
        owner_email = emails[0] if emails else None
        names = payload.get("name") or []
        device_name = names[0] if names else device_id

        compromised = str(payload.get("deviceCompromisedStatus") or "").lower() not in {"safe", "", "unknown"}
        encrypted = str(payload.get("encryptionStatus") or "").lower() == "encrypted"

        obj = NormalizedObject(
            kind="resource",
            provider_id=device_id,
            attributes={
                "name": device_name,
                "resource_type": "device",
                "management_type": "mdm",
                "device_type": payload.get("type"),
                "os": payload.get("os"),
                "status": payload.get("status"),
                "compromised": compromised,
                "encrypted": encrypted,
                "owner_email": owner_email,
                "adb_enabled": bool(payload.get("adbStatus")),
                "developer_options": bool(payload.get("developerOptionsStatus")),
                "model": payload.get("model"),
                "serial_number": payload.get("serialNumber"),
            },
            raw_source=payload,
        )
        return [obj]

    def _normalize_chromeos_device(self, raw: RawObject) -> list[NormalizedObject]:
        """ChromeOS device → resource:device."""
        payload = raw.payload
        device_id = raw.provider_id

        obj = NormalizedObject(
            kind="resource",
            provider_id=device_id,
            attributes={
                "name": payload.get("annotatedAssetId") or payload.get("serialNumber") or device_id,
                "resource_type": "device",
                "management_type": "chromeos",
                "os": payload.get("osVersion"),
                "status": payload.get("status"),
                "compromised": False,
                "encrypted": True,  # ChromeOS is encrypted by default
                "owner_email": payload.get("annotatedUser"),
                "model": payload.get("model"),
                "serial_number": payload.get("serialNumber"),
                "last_sync": payload.get("lastSync"),
                "location": payload.get("annotatedLocation"),
            },
            raw_source=payload,
        )
        return [obj]

    def _normalize_alert(self, raw: RawObject) -> list[NormalizedObject]:
        """Alert Center alert → event or alert_count_setting.

        The synthetic count-summary object (is_count_summary=True) yields
        alert_count_setting rows for HIGH/MEDIUM/LOW. Individual alert objects
        yield events with action=threat.detected.
        """
        payload = raw.payload
        if payload.get("is_count_summary"):
            counts = payload.get("counts") or {}
            objects: list[NormalizedObject] = []
            for severity, count in counts.items():
                objects.append(
                    alert_count_setting(
                        key=f"open_alerts_{severity.lower()}",
                        label=f"Open Alert Center alerts ({severity.capitalize()})",
                        count=int(count),
                        subject_type="application",
                        subject_ref="google_workspace",
                        description=f"Number of open {severity} severity alerts in Alert Center (bodies are not stored).",
                        raw_source=payload,
                        provider_id_prefix="gws-alert-count",
                    )
                )
            return objects

        # Individual alert → event
        alert_id = str(payload.get("alertId") or raw.provider_id)
        severity = str((payload.get("metadata") or {}).get("severity") or "MEDIUM").upper()
        alert_type = str(payload.get("type") or "Unknown alert")
        create_time = payload.get("createTime") or payload.get("startTime")

        return [
            NormalizedObject(
                kind="event",
                provider_id=raw.provider_id,
                attributes={
                    "action": "threat.detected",
                    "action_category": "threat",
                    "actor_email": None,
                    "actor_provider_id": None,
                    "target_email": None,
                    "target_type": "application",
                    "occurred_at": create_time,
                    "summary": f"Alert Center: {alert_type} ({severity})",
                    "attributes": {
                        "alert_id": alert_id,
                        "alert_type": alert_type,
                        "severity": severity,
                        "source": payload.get("source"),
                        "status": (payload.get("metadata") or {}).get("status"),
                    },
                },
                raw_source=payload,
            )
        ]

    def _normalize_inbound_sso_profile(self, raw: RawObject) -> list[NormalizedObject]:
        """Inbound SAML SSO profile → setting."""
        payload = raw.payload
        name = str(payload.get("name") or raw.provider_id)
        display = str(payload.get("displayName") or name)
        idp = payload.get("idpConfig") or {}
        entity_id = str(idp.get("entityId") or "")
        sso_uri = str(idp.get("singleSignOnServiceUri") or "")
        return [
            setting_object(
                key=f"inbound_sso_profile:{name}",
                category="security",
                label=f"Inbound SAML SSO profile: {display}",
                value={"name": name, "displayName": display, "idpEntityId": entity_id, "ssoUri": sso_uri},
                value_type="object",
                description=f"Inbound SAML SSO profile for IdP {entity_id or display}.",
                raw_source=payload,
                provider_id_prefix=f"sso-profile:{name.replace('/', ':')}",
            )
        ]

    def _normalize_inbound_sso_assignment(self, raw: RawObject) -> list[NormalizedObject]:
        """Inbound SSO OU assignment → setting scoped to the OU."""
        payload = raw.payload
        name = str(payload.get("name") or raw.provider_id)
        sso_mode = str(payload.get("ssoMode") or "SSO_OFF")
        target_ou_raw = str(payload.get("targetOrgUnit") or payload.get("orgUnit") or "")
        # targetOrgUnit format: "orgUnits/id:ou-eng" → extract id
        ou_id = target_ou_raw.rsplit("/", 1)[-1] if "/" in target_ou_raw else target_ou_raw
        profile_ref = (payload.get("samlSsoInfo") or {}).get("inboundSamlSsoProfile") or ""

        obj = setting_object(
            key=f"inbound_sso_assignment:{name}",
            category="security",
            label=f"SSO assignment: {sso_mode} ({'OU:' + ou_id if ou_id else 'tenant'})",
            value={"ssoMode": sso_mode, "targetOrgUnit": target_ou_raw, "samlProfile": profile_ref},
            value_type="object",
            description="Inbound SSO mode for this organizational unit (SSO_OFF, SAML_SSO, OIDC_SSO).",
            raw_source=payload,
            provider_id_prefix=f"sso-assign:{name.replace('/', ':')}",
            subject_type="group" if ou_id else None,
            subject_ref=ou_id if ou_id else None,
        )
        if ou_id:
            obj.relationships = [
                NormalizedRelationship(
                    edge_type="applies_to",
                    source_ref=obj.provider_id,
                    target_ref=ou_id,
                )
            ]
        return [obj]

    def _normalize_admin_activity(self, raw: RawObject) -> list[NormalizedObject]:
        """Admin Reports `admin` application events."""
        return _activity_event_objects(raw, _ADMIN_EVENT_TO_KESTREL, app_label="admin")

    def _normalize_drive_activity(self, raw: RawObject) -> list[NormalizedObject]:
        """Admin Reports `drive` application events (external sharing focus)."""
        return _activity_event_objects(raw, _DRIVE_EVENT_TO_KESTREL, app_label="drive")

    def _normalize_saml_activity(self, raw: RawObject) -> list[NormalizedObject]:
        """Admin Reports `saml` application events."""
        return _activity_event_objects(raw, _SAML_EVENT_TO_KESTREL, app_label="saml")

    def _normalize_user_accounts_activity(self, raw: RawObject) -> list[NormalizedObject]:
        """Admin Reports `user_accounts` application events."""
        return _activity_event_objects(raw, _USER_ACCOUNTS_EVENT_TO_KESTREL, app_label="user_accounts")

    def _normalize_groups_activity(self, raw: RawObject) -> list[NormalizedObject]:
        """Admin Reports `groups` application events."""
        return _activity_event_objects(raw, _GROUPS_EVENT_TO_KESTREL, app_label="groups")

    def _normalize_mobile_activity(self, raw: RawObject) -> list[NormalizedObject]:
        """Admin Reports `mobile` application events."""
        return _activity_event_objects(raw, _MOBILE_EVENT_TO_KESTREL, app_label="mobile")

    def _normalize_dwd_client(self, raw: RawObject) -> list[NormalizedObject]:
        """Synthetic DWD client → oauth_application with scopes.

        Marks the client as domain-wide (dwd_client=True) so policies can
        treat it separately from per-user user_token consents.
        """
        payload = raw.payload
        client_id = str(payload.get("client_id") or raw.provider_id)
        app_ref = f"dwd-client:{client_id}"
        scopes = [str(s) for s in (payload.get("scopes") or []) if s]
        has_sensitive = any(is_sensitive_dwd_scope(s) for s in scopes)

        objects: list[NormalizedObject] = [
            NormalizedObject(
                kind="oauth_application",
                provider_id=app_ref,
                attributes={
                    "name": f"DWD client {client_id}",
                    "publisher": "unknown",
                    "client_id": client_id,
                    "dwd_client": True,
                    "revoked": bool(payload.get("revoked")),
                    "has_sensitive_scopes": has_sensitive,
                    "last_changed_at": payload.get("last_changed_at"),
                    "last_changed_by": payload.get("last_changed_by"),
                },
                raw_source=payload,
            )
        ]
        for scope in scopes:
            objects.append(
                NormalizedObject(
                    kind="oauth_scope",
                    provider_id=f"{app_ref}:{scope}",
                    attributes={
                        "oauth_application_ref": app_ref,
                        "scope_name": scope,
                        "is_sensitive": is_sensitive_dwd_scope(scope),
                    },
                    raw_source={"client_id": client_id, "scope": scope},
                )
            )
        return objects
