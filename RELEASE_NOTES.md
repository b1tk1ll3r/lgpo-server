# Release 0.2.2

Export and naming robustness update.

Included:

- `Export-And-Publish.ps1` now treats `GpoName` and repository `PolicyName` as separate concepts.
- `PolicyName` is optional and is automatically normalized when it contains spaces, umlauts, path separators or other unsupported characters.
- The resolved repository name is printed before the AD backup and upload start.
- `-StrictPolicyName` retains fail-fast validation when automatic normalization is not desired.
- `gpoctl` validates policy and profile names locally and reports the offending value before sending an HTTP request.

# Release 0.2.1

Container deployment update.

Included:

- Root-level multi-stage `Dockerfile` for reproducible source builds.
- Root-level `compose.yml` with persistent named volume, healthcheck and log rotation.
- Non-root runtime user, read-only root filesystem, dropped Linux capabilities and `no-new-privileges`.
- Direct TLS and reverse-proxy HTTP modes using the same image.
- `.env.example`, `.dockerignore` and TLS directory guidance.
- Compatibility deployment files under `deploy/`.

Validated in the build environment:

- Compose YAML parsing and environment interpolation.
- Dockerfile structure and build-context completeness.
- Native Go build and complete Go test suite.

A Docker daemon was not available in the build environment, so an actual image build and container startup could not be executed here.

# Release 0.2.0

Web administration release.

Included:

- Embedded, dependency-free German WebUI served directly by `gpo-server` under `/ui/`.
- Dashboard for policy, version, profile and client health metrics.
- Browser upload workflow with semantic duplicate detection, notes and forced versions.
- Full policy/version browsing, administrative artifact retrieval and guarded deletion.
- Ordered profile editor with `latest` or pinned versions and drag-equivalent move controls.
- Searchable and filterable client status view.
- Stateless eight-hour `HttpOnly` admin sessions signed with the admin secret.
- CSRF protection for all cookie-authenticated mutations.
- Restrictive Content Security Policy and additional browser security headers.
- New API deletion endpoints for policies, versions, profiles and stored client reports.
- Conflict protection for policy/profile references and pinned versions.

Validated in the build environment:

- `go test -race ./...`
- `go vet ./...`
- JavaScript syntax validation with Node.js.
- Linux amd64 and Windows amd64 builds.
- HTTP end-to-end flow covering embedded assets, login cookie, CSRF enforcement, Bearer-token compatibility, policy upload, profile creation and client reports.

Browser screenshot automation could not be executed because the managed Chromium installation blocks navigation to local test servers with `ERR_BLOCKED_BY_ADMINISTRATOR`. The UI assets and browser-facing API were still exercised through unit and HTTP integration tests.

# Release 0.1.0

Initial MVP release.

Included:

- File-backed Go server with admin/client authentication.
- Multiple policy objects and immutable versions.
- Semantic change detection for GPO payload files.
- Ordered profiles with `latest` or pinned versions.
- HMAC-signed manifests and SHA-256 artifact verification.
- Windows agent with safe extraction, local LGPO backup, ordered apply, rollback attempt and status reporting.
- Admin CLI and PowerShell deployment scripts.
- Docker, systemd and example configurations.

Validated in the build environment:

- `go test -race ./...`
- `go vet ./...`
- Linux amd64 builds.
- Windows amd64 cross-builds.
- End-to-end server/API test covering upload, duplicate detection, forced versions, `latest` profile resolution, HMAC manifest signature validation and ETag/304 handling.

Not validated in this Linux build environment:

- Execution of `LGPO.exe` on a real Windows Server.
- Scheduled Task registration on each supported Windows Server version.
- Functional equivalence of every possible Group Policy client-side extension.
