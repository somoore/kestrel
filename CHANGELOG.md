# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/). New entries go under **Unreleased**
in one of **Added**, **Changed**, **Fixed**, **Security**, or **Removed**, and
move under a version heading when a release is tagged
(see [`docs/operations/release-process.md`](docs/operations/release-process.md)).

Versions up to 0.5.1 were cut before this repository was published, so they
have no tags or GitHub releases here. Their entries are kept for installs that
started on them.

## Unreleased

### Added

- Policy helpers `now`, `duration_seconds`, `get_path`, `email_domain`,
  `domain_matches`, `ip_in_networks`, and `matches_any`. The two Google
  Workspace duration policies use `duration_seconds` and now read every ISO
  8601 duration (`PT90M`, `P1D`, `P2W`), not just one unit each.
- The policy authoring contract: helpers, builtins, rules, idioms from shipped
  packs, and row shapes, generated from the sandbox. Available from
  `kestrel policy contract` and `GET /api/v1/policies/authoring-contract`,
  and used to build the generate prompt. See
  [Writing policies with an AI agent](docs/policies-for-agents.md).
- AI drafts run over edge-case rows (`probe_test`): missing, string, naive,
  and aware timestamps, another application, and sparse fields. A crash goes
  to the repair turn.

### Changed

- Pull requests that only change Markdown or documentation images run a
  shorter CI gate: Tier 1, the documentation checks, gitleaks, and the commit
  checks. The database tiers, web build, and dependency audits are skipped.
  Pushes to `main` and releases still run everything. See
  [`docs/testing.md`](docs/testing.md#tiers).
- One evaluation pass reads one clock: `now()`, `days_since`,
  `within_last_days`, and `time.time()` in the sandbox are pinned when the
  pass starts, in both runtimes.
- The sandbox's `time` is now a subset of the module, without `sleep`,
  `tzset`, or the process clocks.
- AI generate picks fixtures whose expected matches fit the intent when it has
  them. Otherwise the generic scaffold's result is marked `advisory` and no
  longer drives the repair turn.
- The generate prompt includes up to two shipped pack policies for the
  selected connector.
- `kestrel policy validate` runs the same checks as the API's Validate,
  including unknown names.

### Fixed

- The Google Workspace connector now reads Cloud Identity Policy API
  responses in the shape the API returns. The setting name is taken from
  `setting.type` (minus its `settings/` prefix) instead of the top-level
  `type`, which is the policy kind (`ADMIN` or `SYSTEM`), and the scope is
  taken from `policyQuery.orgUnit` and `policyQuery.group`. The fixtures and
  the ten `gws-posture` policies that read these settings (2-Step
  Verification enforcement and enrollment period, less secure apps, Gmail
  auto-forwarding, Drive external sharing, Marketplace access, Takeout, super
  admin recovery, session length, password policy) now use the documented
  setting names and fields, so they can match a live tenant. Before this, a
  live sync stored every policy under the key `ADMIN` or `SYSTEM` and none of
  the ten policies could open a finding.
- An AI draft that inverts `policy()` (returning `True` for the rows the
  intent asks to flag) is now repaired: the repair turn gets each fixture row
  with what `policy()` must return and what it did, plus an explicit note when
  the logic looks inverted, and the prompt states the return convention with
  an example.
- AI-drafted policies no longer reach for `datetime`, which the sandbox does
  not provide: the generate prompt now lists every policy global (built from
  the helper table), and Validate reports any name the policy reads but
  nothing defines, with a "did you mean" for typos, so the repair pass fixes it
  before the draft reaches the editor. Shipped and stored policies load as before.
- Activating a stored policy version refreshes the policy title even when that
  version reads a name the new authoring check rejects.

## v0.5.4 — 2026-10-26

### Changed

- Policies are described as policies as code, not detections: each one states
  the desired configuration of an application and flags what deviates from it.
  Pack policy titles name the condition instead of starting with "Detect"
  (for example, "GitHub organization administrators without MFA enabled"), and
  descriptions start with "Flags". Slugs are unchanged, so installed policies
  and existing findings keep matching; **Policies → Packs** offers the new
  titles as a pack update.
- The posture scorecard's coverage factor reads "policy coverage gaps" /
  "Policy coverage clear". The `/reports/detection-coverage` endpoint and the
  `detection_gaps` key are unchanged.

### Fixed

- A connector scaffolded by `kestrel connector create` passes its own tests
  before it is wired into the workspace: the scaffold now generates a
  `conftest.py` in its tests directory that puts the connector's `src/` on the
  path.
  Previously `uv run pytest connectors/<name>/tests` failed with
  `ModuleNotFoundError`.
- The connector authoring tutorial's manifest, setup-walkthrough, `client.py`
  and `collector.py` examples had lost their indentation and did not parse
  when copied. A unit test now parses every YAML and Python block in the docs.

### Security

- A dashboard export no longer writes the raw text of an internal error into
  the exported file when a widget's query fails. Such text can include SQL and
  driver detail, and an export is a file that leaves the system. A spec the
  query DSL rejects still shows its message ("filter field not allowed: …");
  any other failure is logged and exported as "query failed".

## v0.5.3 — 2026-10-24

### Added

- Documentation site at [docs.kestrelsecurity.io](https://docs.kestrelsecurity.io/),
  built from `docs/` by `mkdocs.yml` and published to GitHub Pages by the
  release workflow for every release tag (pre-releases excluded). CI builds it
  with `--strict` on every pull request; `make docs-serve` previews it locally.

## v0.5.2 — 2026-10-24

### Changed

- `kestrel init` names the first organization "Kestrel" when `--org-name` is
  not given, instead of "Demo Org". `kestrel demo up` still creates "Demo Org".
- The web app's request filter follows Next.js 16's `proxy.ts` convention
  (formerly `middleware.ts`), which removes the deprecation warning the build
  printed.

### Fixed

- `kestrel demo up` no longer suggests `make demo` when it runs inside the
  Docker deployment, where there is no Makefile.
- The sync pipeline's "unresolved references skipped" warning says how many
  relationships were skipped and of which kinds, instead of a bare event name.
- The api and worker image builds no longer print pip's root-user warning.
- Docs: the Docker quick start says how to move the web UI off port 3000; the
  developer path says that every checkout shares the `kestrel` Compose project;
  the pnpm prerequisite covers Node builds without corepack; `/readyz` is
  listed with the unauthenticated endpoints; the changelog says which versions
  predate this repository; and several wording fixes.

## v0.5.1 — 2026-10-24

### Fixed

- `scripts/license-headers.py` skips the paths a downstream repository lists in
  `.downstream-paths`, as the hygiene denylist already does. A repository that
  carries Kestrel beside its own material no longer fails the hygiene check
  for that material's missing Apache-2.0 headers.

## v0.5.0 — 2026-10-24

### Added

- Policies can be deleted permanently, from the policy page or the list's row
  menu: `DELETE /policies/{id}` removes the policy, its versions, evaluation
  history, findings and everything attached to them. System policies refuse;
  pack policies come back (without findings) when the pack is installed again.
- The policies list is paged, 25 per page by default with 50 and 100 as
  options, with numbered page links instead of one long scroll inside the
  page. Changing a filter, sort, or search returns to the first page.
- The policies list row menu can also enable or disable a policy in place.
- The dashboard's getting-started checklist can be dismissed, from the card's
  × or its menu, so it stops showing before setup is complete. The choice is
  per operator (`POST /dashboard/first-run/dismiss`), and "Show
  getting-started checklist" in the board menu brings it back.

### Changed

- Policy search matches every word of the query, in any order, against the
  title, slug and its parts, pack name, application, severity, and resource
  type, so "okta mfa" and "github-posture" both narrow the list.

### Fixed

- The policy workbench's dormant-admin intent template now matches "has not
  signed in", "not logged in", "no login activity", and "N days" phrasings, so
  "Detect Okta admin that has not signed in within last 90 days" drafts
  offline instead of going to the AI provider.
- The generic Okta and GitHub identity fixture pairs carry a `last_active_at`
  on each row. An AI-drafted dormancy policy was failing its fixture test
  against rows with no sign-in time, flagging both admins, and the repair
  pass was then asked to "fix" a policy that was right.
- OpenAI's `credit_balance_exhausted` error is reported as a billing problem
  ("quota exceeded, check billing") instead of as rate limiting, and the
  server log records the provider's error code and message on every AI draft
  failure.

### Security

- OpenTelemetry 1.45.1 (API, SDK and OTLP/HTTP exporter) fixes
  CVE-2026-114603 in `opentelemetry-api`; the dependency floors now require it.
- zod 4.6.7 fixes a memory exhaustion when validating oversized constrained
  collections (GHSA-mrhx-c7xc-m3w5). It is reached only through lint tooling
  (`eslint-config-next`), not the web app's bundle.

## v0.4.2 — 2026-10-22

### Security

- Next.js 16.4.2 (from 16.4.0) fixes two unauthenticated remote code execution
  advisories (GHSA-2464-fhr4-w9xw, GHSA-673q-mjm6-r5xr) and an App Router denial
  of service (CVE-2026-94482).
- certifi 2026.10.19 drops the emSign root CAs with compromised keys
  (GHSA-6q48-6c7w-9gw2).
- dompurify 3.4.17 (through monaco-editor) fixes two sanitizer bypasses
  (GHSA-cg2g-xh64-v4q7, GHSA-mrv2-3pqr-j5jr), and vite 8.2.4 fixes
  GHSA-587h-7wmj-h5pm in the web build tooling.
- The api and worker images no longer ship uv. It is installed, used and
  removed in one build step, so its bundled CA store (GHSA-hq85-5cpj-mr62) is
  not in the image; nothing at runtime used it.

## v0.4.1 — 2026-10-17

### Added

- `scripts/docs-check.sh` and `scripts/oss-hygiene.sh` skip the paths listed in
  an optional `.downstream-paths` file, so a repository that carries a Kestrel
  release next to its own infrastructure can run Kestrel's CI unchanged
  ([deployment docs](docs/deployment.md#running-from-your-own-repository)).

## v0.4.0 — 2026-10-10

The first public release of Kestrel, open-source security for SaaS.

### Launch hardening

- Policy IDs are restricted to portable filename-safe identifiers. GitOps
  export independently rejects unsafe stored IDs, symlink destinations and
  colliding filenames before writing policy files.
- MFA consumes TOTP/recovery codes and login challenges under database locks,
  so overlapping requests cannot reuse a code or challenge to mint sessions.
- Python dependency auditing explicitly targets the locked workspace. Releases
  require CI, security scans, system tests and all three container scans on the
  tagged commit; an already-prepared version can be tagged with `--prepared`.
- uv is pinned to 0.12.18 across the workspace, CI and Python images, restoring
  compatibility with Python Dependabot updates without changing dependency versions.
- For MFA-enrolled operators a correct password no longer resets the failed
  attempt counter; only a successful second factor does, closing a lockout
  bypass by repeated sign-in. MFA enrolment-only sessions expire after 15 minutes.
- Only an org dashboard's owner or an admin can change it or its widgets; Home is
  admin-only. API tokens cannot mint API tokens, and token lifetimes are 1–365
  days. Deactivating an operator revokes their sessions and API tokens.
- `POST /findings/{id}/verify` with a sync applies the Sync-now guards; verify and
  policy generation are in the expensive rate-limit tier. Login and policy-intent
  inputs have length caps.
- Webhook deliveries are row-locked against double sends and read at most 64 KiB
  of an error body; tracker transport failures return a 400, not a 500.
- The web app sends a nonce-based Content-Security-Policy (and HSTS over https),
  bundles the Monaco editor instead of loading it from a CDN, validates every id
  before it reaches an API path, and treats only single-`/` links as in-app.
- An expired session now redirects to sign-in from every action instead of
  reporting "Request failed"; an unreachable API is reported as such rather than
  as "not initialized"; finding actions show their errors inline.
- Policies may use augmented assignment (`count += 1`). Collapsed identity lists
  page past the first page. GitHub GraphQL walks fail loudly instead of
  truncating at 100 pages. The findings keyboard shortcuts no longer capture keys
  aimed at links, buttons, and menus. The demo's example webhooks are seeded
  disabled so re-running the demo cannot build a pending delivery backlog.
- The identity page labels each role and OAuth grant with the application it
  belongs to, not the account being viewed. The demo's Okta tenant lists its
  admins in `/iam/assignees`, so direct Okta roles (including the drift
  timeline's Super Administrator promotion) are collected, and `demo up`
  disables policies from packs that are no longer in `packs/`.
- Documentation: NIST mappings are labelled CSF 1.1 (what the packs use); the
  production Compose stack passes `deployments/compose/.env` through to every
  service; every `KESTREL_*` variable is in `.env.example`; new FAQ, permissions
  table, clean-up steps, and refreshed screenshots (`make screenshots`).

### Added

- **Connector SDK** — a Protocol-based interface with fixture and live
  transports, manifest validation, and read-only scope enforcement, so a
  connector can be built and tested without touching core
  ([`docs/connectors.md`](docs/connectors.md)).
- **First-party connectors** for GitHub, Google Workspace, Okta, and Slack, each
  mapped against a published baseline (CIS GitHub Benchmark, CISA SCuBA, DISA
  Okta STIG, NIST CSF / CIS Controls), plus a worked custom-connector example
  under `examples/custom-connector`.
- **Normalized identity and access graph** in PostgreSQL — users, groups, roles,
  permissions, resources, settings and OAuth grants, distinguishing direct,
  inherited, and OAuth-derived access, with `raw_source` provenance on every
  row ([`docs/identity-graph.md`](docs/identity-graph.md)).
- **Change feed** — every sync snapshots the graph and diffs it against the
  previous one into classified changes ([`docs/changes.md`](docs/changes.md)).
- **Python policies** — `policy(resource)` functions compiled with
  RestrictedPython and run in an isolated subprocess, testable against fixtures,
  versioned in git, and shipped in posture packs with compliance mappings;
  AI-assisted drafts stay behind a human review gate
  ([`docs/policies.md`](docs/policies.md)).
- **Findings workbench** — evidence, remediation guidance, notes, watchers,
  exceptions, playbooks, verification, and GitHub Issues / Jira ticketing
  ([`docs/findings.md`](docs/findings.md)).
- **Explore** graph canvas, **dashboards** with a constrained metric language
  (findings, connector health, and a daily posture trend), PDF/CSV export and
  scheduled email, and saved searches.
- **Toxic combinations** — named attack-path rules over the open findings on one
  subject, opened and resolved as findings of their own after each evaluation.
- **Operator authentication** — opaque session and API tokens, three roles,
  Argon2id, lockout, rate limits, and an audit log. Connector credentials are
  envelope-encrypted at rest; outbound requests are SSRF-guarded.
- **Personal notifications** — finding open/resolve events (org-wide by
  preference, or for findings you watch) and webhook delivery failures arrive in
  an in-app inbox behind the sidebar bell (`/api/v1/notifications`) and, when
  email is set up, by email; watchers also get a weekly watched-findings
  digest. Each operator controls channels and thresholds in Settings →
  Notifications ([`docs/findings.md`](docs/findings.md#notifications)).
- **Email settings** — admins set the organization's mail server (SMTP host,
  security, credentials, sender) at Settings → Email and send a test message;
  the password is encrypted at rest. The `KESTREL_SMTP_*` environment remains
  an optional deployment-wide default.
- **Two-factor authentication** — TOTP authenticator apps with single-use
  recovery codes; admins can require it for every operator, and reset a lost
  device from Settings → Operators or `kestrel operator reset-mfa`.
- **Password management** — operators change their own password at Settings →
  Account; admins reset anyone else's from Settings → Operators with a
  generated, shown-once temporary password that ends their sessions.
- **Operations** — scheduled syncs, HMAC-signed outbound webhooks, GitOps
  export / plan / apply, Prometheus metrics and OpenTelemetry tracing.
- **Docker deployment** — Dockerfiles for the api, worker and web images on the
  official `python` and `node` base images; `deployments/compose/` builds them and
  runs migrations automatically; `kestrel init` bootstraps the first admin
  inside the container ([`docs/deployment.md`](docs/deployment.md)). A fixture
  demo (`kestrel demo up`) loads four realistic tenants with no cloud
  credentials ([`docs/demo.md`](docs/demo.md)).

### Security

Security properties of this first release, beyond operator authentication:

- **No default admin login.** `kestrel init` gives the first admin a random
  password, printed once, unless one is passed explicitly. The published
  development password is opt-in (`--dev-password`, source checkouts only) and
  is what `kestrel demo up` and `make seed` use locally.
- **The master key must be at least 32 bytes.** API startup rejects a shorter
  configured `KESTREL_MASTER_KEY` (or `KESTREL_MASTER_KEY_PREVIOUS`) with a message
  saying how to generate one.
- **Stored secrets are bound to the row they belong to.** Every ciphertext
  (connector credentials, webhook signing secrets, ticketing tokens, LLM API
  keys, TOTP secrets, SMTP passwords) carries its table, row, and field as
  AES-GCM associated data, so a ciphertext copied onto another row by someone
  with database write access fails to decrypt instead of silently working.
  Rows written by pre-release builds keep decrypting until re-encrypted: run
  `kestrel secrets rotate` once after upgrading (fresh 0.4.0 installs have none).
- **The master key can be rotated.** Each stored secret records the id of the
  key that encrypted it. Set `KESTREL_MASTER_KEY_PREVIOUS` to the retiring
  key, restart, and `kestrel secrets rotate` re-encrypts every row under the
  new `KESTREL_MASTER_KEY`; `kestrel secrets status` shows what is left
  ([`docs/deployment.md`](docs/deployment.md)).
- **Connector credentials never follow a changed URL.** Changing a connector's
  URL or host config clears its stored secrets unless new ones are sent with
  the change (recorded in the audit log), and changing the Jira or AI provider
  base URL requires the token or key again. Live connector URLs and webhook
  endpoints must use `https`; Okta org URLs must be on Okta-owned domains.
- **Outbound requests are SSRF-guarded.** Every operator-supplied URL is
  rejected unless it resolves to a globally routable address; cloud-metadata
  addresses are refused even when allowlisted (`KESTREL_CONNECTOR_URL_ALLOWLIST`).
- **Policy code is sandboxed.** Policies compile with RestrictedPython, may only
  define constants and functions at module level, run in a subprocess with
  wall-clock, CPU, and memory limits, and each gets its own copy of the rows it
  evaluates. The worker child starts with an allowlisted environment, so
  `KESTREL_MASTER_KEY`, `DATABASE_URL`, `REDIS_URL`, and provider credentials
  never reach policy code even if it escaped RestrictedPython. Compiling,
  testing, and dry-running policies requires the analyst role.
- **Policy module bodies cannot rebind what the compiler trusts.** `tuple`,
  `frozenset`, the shared helpers and `time` may not be reassigned or shadowed
  at module level, closing a way to make the API hash an exponentially nested
  literal at compile time.
- **Account-security changes need a signed-in session.** Password changes,
  two-factor enrolment and recovery-code regeneration refuse API tokens, which
  never passed a second factor; API token creation and revocation are audited.
- **Admins cannot lock the organization out.** An admin cannot deactivate or
  demote their own account or the last active admin.
- **Mail server connections verify the certificate.** SMTP over STARTTLS or
  SSL/TLS uses a verifying TLS context; the stdlib default checked nothing.
- **Demo accounts have no password on a deployment.** `kestrel demo up` only
  gives its seeded team accounts the published dev password in a local
  checkout.
- **Webhook retries stop when they cannot succeed.** A disabled endpoint, a
  rejected URL or a 4xx is failed once and reported; transient failures back
  off exponentially; an event already delivered is never posted twice.
- **Login is rate-limited per client and per account.** The client IP comes from
  `X-Forwarded-For` only for peers in `KESTREL_TRUSTED_PROXIES`; unknown
  accounts take as long to reject as a wrong password; failed attempts are
  counted atomically toward the lockout.
- **Changing a password ends other sessions**; an admin reset also revokes the
  operator's API tokens by default.
- **CSV exports neutralise spreadsheet formulas**, and webhook error bodies are
  stored as a short plain-text summary.
