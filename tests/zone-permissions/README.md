# Zone permission startup regressions

This Go standard-library-only black-box suite adds coverage for an **already
merged and released fix**, not another implementation. Shreyas Zare fixed the
missing null check and the incorrect Administrators/DNS Administrators target in
`InspectAndFixZonePermissions()` in upstream commit
[`9dcb17c921c373f43e024155e31e8c55ce8e3d83`](https://github.com/TechnitiumSoftware/DnsServer/commit/9dcb17c921c373f43e024155e31e8c55ce8e3d83).
The fix is included in [v15.6.2](../../CHANGELOG.md#version-1562); v15.6.1 predates
it. No production C# code is changed by this suite.

## Run

Requirements: Go 1.22 or newer, the Docker CLI, and an authorized **local Linux
Docker daemon**. Pull official images explicitly; tests use `--pull=never`.
There are no Go dependencies to download.

From the repository root, keep build and test temporary files on the workspace
disk (rather than a potentially small system temporary filesystem):

```sh
mkdir -p .git/zone-permissions-test/go-cache .git/zone-permissions-test/tmp
export GOCACHE="$PWD/.git/zone-permissions-test/go-cache"
export GOTMPDIR="$PWD/.git/zone-permissions-test/tmp"
export TMPDIR="$GOTMPDIR"
export GOTOOLCHAIN=local
export GOPROXY=off
export GOSUMDB=off

docker pull technitium/dns-server:15.6.1
docker pull technitium/dns-server:15.6.2
cd tests/zone-permissions
gofmt -w startup_test.go
go vet ./...
go test -count=1 -timeout 5m -v ./...

# RED: both sibling cases must fail against this pre-fix release.
TECHNITIUM_TEST_IMAGE=technitium/dns-server:15.6.1 \
  go test -count=1 -timeout 5m -v ./...

# GREEN: both cases must pass against the released fix.
TECHNITIUM_TEST_IMAGE=technitium/dns-server:15.6.2 \
  go test -count=1 -timeout 5m -v ./...
```

Without `TECHNITIUM_TEST_IMAGE`, the integration test explicitly skips. Once it
is set, missing Docker/images, failed API calls, crashes, and readiness timeouts
are failures, not skips. Docker commands have 30-second limits, container-local
HTTP requests have 3-second limits, and each startup has a 30-second readiness window.

## Coverage and isolation

- **MissingACL:** create a user, custom group, and existing zone ACL through the
  native POST API; gracefully stop to snapshot their generated `auth.config`.
  Restart and create another zone, stop to persist its zone file, then restore
  only the earlier auth snapshot. Startup must recover the missing ACL.
- **UnderprivilegedDNSAdministrators:** create an existing zone permission with
  custom user/group grants. The API always enforces full administrator grants,
  so, while stopped, downgrade only that zone's DNS Administrators flag byte
  from 7 to 1 in the generated fixture. The patch validates the unique
  synthetic zone, permission version/section, original flag, and leaf shape;
  unsupported fixture formats fail explicitly.

Both cases require **Administrators = 7 and DNS Administrators = 7**, where
View/Modify/Delete are 1/2/4. They require exact preservation of the existing
user grant (3) and custom group grant (5), and log in as the existing user to
read its existing zone ACL. After each graceful stop, the test also inspects
the saved DNS Administrators flag before another startup can repair it again.
A further graceful restart checks idempotent recovery. Docker process state is checked during readiness because
the old startup crash can exit with code **0**.

Every case uses a fresh container with `--network=none`: no ports are published
and there is no external egress. Its bundled `curl` makes management requests
only to its own loopback via `docker exec -i`; request configuration, credentials,
and POST bodies travel on stdin. No host networking, host configuration, Docker
socket, or existing state are mounted. Recursion and blocking are disabled. Initialization variables follow
[`DockerEnvironmentVariables.md`](../../DockerEnvironmentVariables.md).

Passwords are randomly generated and sent in the Docker command environment or
POST bodies, not command arguments or URLs. Host fixtures use a fresh mode-0700
`t.TempDir`; auth snapshots are mode 0600. `docker cp` transfers only synthetic
fixtures while the server is stopped. Root-owned live state stays in the
container's disposable filesystem, so native `docker rm --force --volumes`
handles cleanup without recursive host deletion or a cleanup sidecar. Cleanup is
registered before creation, reconciles the generated container name, and refuses
deletion without its matching ownership label. A daemon/cleanup failure is reported,
not treated as success. Failures include bounded container logs
with generated passwords and session tokens redacted; auth contents and API
bodies are never dumped.
