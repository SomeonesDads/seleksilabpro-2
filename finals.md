# Remaining Specification Work

This document lists the specification work that is not complete in the current
checkout. It is based on `SPECS.md`, the repository implementation, the existing
architecture decisions in `DECISIONS.md`, and the current Compose layout.

The four changes described in `todo.md` are treated as completed work. They do
not complete the rest of the assignment: the control panel, relying
applications, production wiring, and several bonus requirements are still
unfinished.

## 1. Control Panel Admin — F02

### Current gap

`auth-provider/control-panel/internal/handlers/handlers.go` returns
`501 Not Implemented` for the dashboard, users, groups, and applications pages.
The control panel therefore does not provide the administration functions
required by F02.

### Required behavior

The control panel must be a thin HTML client of the Auth Provider Server's
`/admin/*` API. It must not connect to or query PostgreSQL directly.

It must allow an administrator to:

- view a dashboard containing users, groups, applications, and policy status;
- create, view, update, activate, and deactivate users;
- create and manage groups;
- add and remove users from groups;
- register applications and redirect URIs;
- view applications and their policies;
- assign and remove group allow-policies per application;
- display API failures as safe, understandable messages without exposing
  secrets, hashes, stack traces, or internal database details.

The control panel must forward the administrator's authenticated identity to
the server using the agreed admin-session mechanism. It must not invent a
second authorization model that bypasses the server middleware.

### Testable acceptance criteria

- `GET /`, `/users`, `/groups`, and `/applications` return HTML `200` pages
  when the admin session is valid; none returns `501`.
- Each required form submits to the corresponding Auth Provider `/admin/*`
  endpoint and renders the returned success or error state.
- A browser-level or handler integration test proves the panel makes HTTP
  requests to the Auth Provider and never opens a database connection.
- Tests cover user CRUD/status, group membership, application registration,
  redirect URI registration, policy assignment, and policy removal.
- A request without a valid admin session is rejected and cannot perform an
  admin mutation.
- Returned application client secrets are shown only in the provisioning
  response and are not rendered into later pages or logs.

## 2. Relying Application App A — F04

### Current gap

The `applications/app-a` source tree, Dockerfile, configuration, local schema,
and HTTP handlers are absent. Compose references the directory, but there is
no implementation to build or run.

### Required behavior

App A must not store user credentials. It must implement the OAuth authorization
code flow through the Auth Provider:

1. start login by creating and storing a state value server-side;
2. redirect the browser to `/authorize` with `response_type=code`, client ID,
   exact redirect URI, state, and S256 PKCE parameters;
3. validate state in the callback;
4. exchange the code server-to-server at `/token`;
5. call `/userinfo` with the access token and App A client authentication;
6. create an independent local session and profile cache;
7. render the authenticated user's identity and App A status;
8. support local logout and receive authenticated internal revocation events.

The app must expose the required local-session status, activity log, processed
events, login/logout controls, and safe error messages. It must persist only
hashed local session tokens, Auth Provider user references, profile data, and
processed-event records; it must never persist passwords, password hashes,
client secrets in local sessions, raw session tokens, or redeemed authorization
codes.

### Testable acceptance criteria

- A fresh browser can complete login, callback, code exchange, UserInfo, and
  local-session creation against a running Auth Provider.
- A tampered or replayed state is rejected without creating a local session.
- A wrong redirect URI, wrong verifier, expired code, or reused code produces a
  safe error page and no session.
- App A displays the Auth Provider profile cache, local-session status and
  timestamps, activity log, and processed-event list.
- Local logout revokes only the App A local session.
- A duplicate `eventId` is acknowledged idempotently and does not repeat the
  revocation work.
- `SessionRevoked`, `PasswordChanged`, and App-A-scoped
  `AccessPolicyChanged` events revoke the correct local sessions.
- Database tests prove no prohibited credential or raw-token fields are stored.

## 3. Relying Application App B — F04

### Current gap

The `applications/app-b` source tree, Dockerfile, configuration, local schema,
and HTTP handlers are absent. Compose references the directory, but there is
no implementation to build or run.

### Required behavior

App B must implement the same relying-application contract as App A, using its
own client ID, redirect URI, local database, local session store, profile cache,
event inbox, and internal logout endpoint. Its local sessions must be
independent from App A's sessions.

### Testable acceptance criteria

- App B completes the full login and callback flow independently of App A.
- App A logout does not revoke App B's local session.
- SSO logout or password change revokes both applications when both have issued
  tokens for the affected central session.
- An App-B-scoped policy-loss event revokes App B only.
- App B rejects invalid internal event authentication and accepts a valid,
  idempotent event exactly once.
- App B has the required identity, session-status, activity, processed-events,
  login, logout, and safe-error UI.

## 4. Auth Provider Production Wiring and Cross-Service Integration

### Current gap

The server owns the outbox records, but the server process does not connect to
RabbitMQ or publish events. The worker contains the outbox publisher and
consumer, but the complete running flow cannot be demonstrated without App A
and App B. The `cmd/seed` command is also still a placeholder, so there is no
repeatable way to provision demo users, groups, applications, redirect URIs,
policies, and worker target credentials.

### Required behavior

- Every security-critical revocation change writes its outbox event in the same
  transaction as the state change.
- The outbox publisher publishes only supported exact event types, uses broker
  confirms, and marks an event published only after confirmation.
- The worker resolves only configured, authenticated application targets,
  records per-application delivery state, retries transient failures, and sends
  permanent failures to the native DLQ.
- Seed data is idempotent and creates a usable demo environment without
  printing or persisting raw passwords or client secrets beyond the intended
  provisioning output.

### Testable acceptance criteria

- A disposable PostgreSQL/RabbitMQ integration test proves logout creates one
  outbox row and that the row survives a worker restart until confirmed.
- Publisher-confirm failure leaves `published_at` unset and permits retry.
- Unknown event types are not routed to the worker.
- Worker tests prove independent App A/App B delivery, bounded retry/backoff,
  idempotent processing, and DLQ routing after permanent failure.
- A second execution of the seed command creates no duplicate users, groups,
  applications, policies, or redirect URIs.
- A clean demo run can execute login -> authorize -> token -> UserInfo -> local
  sessions -> SSO logout -> asynchronous local-session revocation.

## 5. Server Cross-Endpoint Requirements Still Requiring Closure

The checklist in `SPECS.md` sections A–C remains unchecked and must be verified
as a complete contract, even where individual code paths already exist.

### Required behavior

- Handlers only orchestrate use cases; SQL, transactions, and security
  invariants remain in repositories.
- All required repository ports and TTL/JWT configuration are injected.
- Every error uses the standard `{ "error": { "code", "message", "requestId" } }`
  envelope.
- Credential failures are generic and do not disclose account existence,
  hashes, tokens, secrets, policy details, or stack traces.
- Passwords, session tokens, authorization codes, and pending-MFA tokens are
  hash-only at rest.
- Central-session and pending-MFA cookies are `HttpOnly`, `Secure`,
  `SameSite=Lax`, `Path=/`, and expiring.
- Required audit events exist for successful and failed login, denied access,
  authorization-code issuance, token issuance, logout, and MFA outcomes.
- Login intents are validated authorization requests, not trusted hidden form
  values.
- Authorization validates every required parameter, inactive clients,
  exact redirect URI equality, active sessions/users, PKCE S256, policy allow,
  safe denial, and one-time hashed authorization codes.

### Testable acceptance criteria

- Unit and handler tests cover every A–C bullet, including malformed and
  duplicate query parameters.
- Tests inspect response bodies and `Set-Cookie` attributes, not only status
  codes.
- Tests prove no session or authorization code is created on invalid login
  intents, invalid redirect URIs, policy denial, or failed MFA.
- Concurrent code redemption produces exactly one success and one failed
  redemption.
- Repository rollback tests prove state changes and outbox writes commit or
  roll back together.
- The focused command and full command from `SPECS.md` pass with disposable
  PostgreSQL available.

## 6. Bonus B02 — Observability

### Current gap

`GET /metrics` is not mounted and no Prometheus metrics are implemented.

### Required behavior

Expose a Prometheus-compatible metrics endpoint from the Auth Provider web
application. Metrics must reflect real runtime behavior and include at least:

- request rate, error count, and request duration;
- authentication and authorization failures;
- outbox/queue depth;
- worker delivery attempts, successes, retries, permanent failures, and DLQ
  count;
- database/broker health state where applicable.

### Testable acceptance criteria

- `GET /metrics` returns `200` and valid Prometheus exposition text.
- Login/logout requests change request and error counters and duration data.
- Creating an unpublished event changes the outbox/queue-depth metric.
- Stopping delivery increases the relevant retry/DLQ metrics; restoring the
  worker changes them again.
- No metric uses hardcoded queue or worker values.

## 7. Bonus B03 — Complete Readiness Probe

### Current gap

Liveness and readiness routes exist, but readiness checks only PostgreSQL and
does not check RabbitMQ.

### Required behavior

- `/health/live` returns `200` while the process is responsive and does not
  depend on external services.
- `/health/ready` checks PostgreSQL, RabbitMQ, and every dependency required for
  Auth Provider operation.
- Readiness returns `503` with safe per-component status when any dependency is
  unavailable, and returns `200` only when all are healthy.
- Recovery of a dependency is reflected without restarting the server.

### Testable acceptance criteria

- Database stopped: liveness remains `200`, readiness becomes `503`.
- RabbitMQ stopped: liveness remains `200`, readiness becomes `503` and names
  the broker as unavailable.
- Both dependencies restored: readiness returns `200` and reports both healthy.
- Probe output contains no connection strings, credentials, stack traces, or
  internal error details.

## 8. Bonus B04 — Complete Graceful Shutdown

### Current gap

The server drains HTTP requests but has no broker consumer/publisher to stop in
its process and still contains a TODO for broker shutdown. The full shutdown
contract must be verified across server, publisher, and worker.

### Required behavior

- Stop accepting new HTTP requests.
- Stop consuming new broker deliveries on termination.
- Allow in-flight requests, publishing, and event deliveries to finish within
  `SHUTDOWN_TIMEOUT`.
- Safely ACK completed work or leave unfinished broker messages available for
  redelivery.
- Close broker and database connections after draining.
- Cancel stuck work at the timeout and exit without hanging indefinitely.

### Testable acceptance criteria

- A long-running HTTP request completes before shutdown returns when within the
  timeout.
- No new message is accepted after intake is stopped.
- An in-flight successful delivery is durably marked and ACKed before exit.
- An interrupted delivery is not falsely marked successful and is redelivered
  or dead-lettered according to the retry policy.
- Shutdown completes within the configured timeout when a dependency hangs.
- Repeated shutdown signals do not panic or double-close resources.

## 9. Build, Compose, and Verification Closure

### Current gap

Compose references missing `applications/app-a`, `applications/app-b`, and
root `go.work`; the control-panel image also references a missing `web`
directory. The server requires Go 1.25 while the Dockerfiles use Go 1.22.
The control-panel and sync-worker modules do not currently have checked-in
`go.sum` files.

### Required behavior

The documented command `docker compose up --build` must build and start the
complete stack with the example environment files in the exact paths expected
by Compose. Module versions, Docker builder versions, local replacements, and
copied source paths must agree.

### Testable acceptance criteria

- `docker compose config` succeeds with all referenced files present.
- `docker compose build` succeeds for every service.
- `docker compose up --build` reaches healthy PostgreSQL/RabbitMQ and starts
  Auth Provider, control panel, worker, App A, and App B.
- Each module passes `go test ./...` from its own module directory.
- `go vet ./...` passes for the server and any newly added services.
- No `.env`, raw credential, generated build cache, or temporary database file
  is committed.

## Definition of complete

This work is complete only when:

1. all required F02, F04, and F05 user-visible flows are runnable;
2. App A and App B can independently log in and receive revocations;
3. the control panel performs every required admin operation through the
   server API;
4. the server, worker, and broker preserve transactional-outbox and delivery
   invariants;
5. the Compose stack builds and starts from a clean checkout;
6. the acceptance tests above pass with disposable PostgreSQL and RabbitMQ;
7. implemented bonus behavior is either completed and tested or clearly left
   out of the claimed deliverables.

