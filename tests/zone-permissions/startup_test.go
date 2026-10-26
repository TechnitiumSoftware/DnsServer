package zonepermissions

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	existingZone = "existing.example.test"
	repairedZone = "repair.example.test"
	fixtureUser  = "regression-reader"
	fixtureGroup = "Regression Auditors"
)

func TestZonePermissionStartup(t *testing.T) {
	image := os.Getenv("TECHNITIUM_TEST_IMAGE")
	if image == "" {
		t.Skip("set TECHNITIUM_TEST_IMAGE to a locally pulled official Technitium image")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"MissingACL", "UnderprivilegedDNSAdministrators"} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t, image)
			admin := s.login("admin", s.adminPassword)
			s.mustAPI("/api/admin/users/create", admin, url.Values{
				"user": {fixtureUser}, "pass": {s.userPassword},
			})
			s.mustAPI("/api/admin/groups/create", admin, url.Values{"group": {fixtureGroup}})
			s.mustAPI("/api/admin/users/set", admin, url.Values{
				"user": {fixtureUser}, "memberOfGroups": {fixtureGroup},
			})
			s.mustAPI("/api/admin/permissions/set", admin, url.Values{
				"section": {"Zones"}, "userPermissions": {fixtureUser + "|true|true|false"},
			})
			s.createZone(admin, existingZone, true)
			missing := name == "MissingACL"
			if !missing {
				s.createZone(admin, repairedZone, true)
			}

			// Stopping flushes the native deferred auth and zone-file saves.
			s.stop()
			authFile := filepath.Join(s.fixtures, "auth.config")
			s.mustDocker("cp", s.container+":/etc/dns/auth.config", authFile)
			if err := os.Chmod(authFile, 0600); err != nil {
				t.Fatal(err)
			}
			auth, err := os.ReadFile(authFile)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(auth, []byte{'A', 'S', 4}) {
				t.Fatal("unsupported synthetic auth.config format; expected AS version 4")
			}

			if missing {
				if bytes.Contains(auth, []byte(repairedZone)) {
					t.Fatal("the earlier auth snapshot already contains the new zone")
				}
				s.start()
				s.createZone(s.login("admin", s.adminPassword), repairedZone, false)
				s.stop()
			} else {
				weakenDNSAdministrators(t, auth)
				if err := os.WriteFile(authFile, auth, 0600); err != nil {
					t.Fatal(err)
				}
			}
			zoneFile := filepath.Join(s.fixtures, "repair.zone")
			s.mustDocker("cp", s.container+":/etc/dns/zones/"+repairedZone+".zone", zoneFile)
			if info, err := os.Stat(zoneFile); err != nil || info.Size() == 0 {
				t.Fatalf("new zone file was not persisted: %v", err)
			}
			s.mustDocker("cp", authFile, s.container+":/etc/dns/auth.config")

			for _, phase := range []string{"recovery", "persisted recovery"} {
				t.Log(phase)
				s.start()
				s.checkACL(s.login("admin", s.adminPassword), repairedZone, !missing)
				s.checkACL(s.login(fixtureUser, s.userPassword), existingZone, true)
				s.stop()
				// Check saved bytes so a later repair cannot conceal a failed save.
				persisted := filepath.Join(s.fixtures, "persisted-auth.config")
				s.mustDocker("cp", s.container+":/etc/dns/auth.config", persisted)
				if err := os.Chmod(persisted, 0600); err != nil {
					t.Fatal(err)
				}
				saved, err := os.ReadFile(persisted)
				if err != nil {
					t.Fatal(err)
				}
				dnsAdministratorsOffset(t, saved)
			}
		})
	}
}

type server struct {
	t                           *testing.T
	image, container, fixtures  string
	adminPassword, userPassword string
	secrets                     []string
}

func newServer(t *testing.T, image string) *server {
	t.Helper()
	s := &server{
		t: t, image: image, fixtures: t.TempDir(),
		adminPassword: randomSecret(t), userPassword: randomSecret(t),
	}
	s.secrets = []string{s.adminPassword, s.userPassword}
	if err := os.Chmod(s.fixtures, 0700); err != nil {
		t.Fatal(err)
	}
	t.Logf("image %s (%s)", image, s.mustDocker("image", "inspect", "--format", "{{.Id}}", image))
	name := "zone-permissions-" + randomSecret(t)[:16]
	s.container = name
	// Register by the generated name before acquisition: Docker may create a
	// resource even when its CLI loses the response or reaches its deadline.
	t.Cleanup(func() {
		owner, err := s.docker("inspect", "--format", "{{index .Config.Labels \"technitium.zone-permissions-test\"}}", name)
		if err != nil {
			t.Errorf("cannot reconcile test container cleanup: %v", err)
			return
		}
		if owner != name {
			t.Error("refusing to remove a container without this test's ownership label")
			return
		}
		if t.Failed() {
			logs, err := s.docker("logs", "--tail", "80", s.container)
			if err != nil {
				t.Error(err)
			} else {
				t.Logf("test server logs (credentials redacted):\n%s", s.redact(logs))
			}
		}
		if _, err := s.docker("rm", "--force", "--volumes", s.container); err != nil {
			t.Error(err)
		}
	})
	s.mustDocker("create", "--pull=never", "--name", name,
		"--label", "technitium.zone-permissions-test="+name,
		"--network", "none", "--hostname", "dns.example.test",
		"--restart=no", "--stop-timeout", "10",
		"--env", "DNS_SERVER_DOMAIN=dns.example.test",
		"--env", "DNS_SERVER_ADMIN_PASSWORD",
		"--env", "DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=0.0.0.0",
		"--env", "DNS_SERVER_WEB_SERVICE_HTTP_PORT=5380",
		"--env", "DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS=false",
		"--env", "DNS_SERVER_RECURSION=Deny",
		"--env", "DNS_SERVER_ENABLE_BLOCKING=false",
		"--env", "DNS_SERVER_STATS_ENABLE_IN_MEMORY_STATS=true", image)
	s.start()
	return s
}

func randomSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func (s *server) redact(text string) string {
	for _, secret := range s.secrets {
		text = strings.ReplaceAll(text, secret, "[redacted]")
	}
	return text
}

func (s *server) docker(args ...string) (string, error) {
	return s.dockerInput("", args...)
}

func (s *server) dockerInput(input string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = append(os.Environ(), "DNS_SERVER_ADMIN_PASSWORD="+s.adminPassword)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", args[0], err, s.redact(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func (s *server) mustDocker(args ...string) string {
	s.t.Helper()
	output, err := s.docker(args...)
	if err != nil {
		s.t.Fatal(err)
	}
	return output
}

func (s *server) state() string {
	s.t.Helper()
	return s.mustDocker("inspect", "--format",
		"{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}", s.container)
}

func (s *server) start() {
	s.t.Helper()
	s.mustDocker("start", s.container)
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if state := s.state(); state != "running exit=0 oom=false" {
			s.t.Fatalf("management startup failed: container %s (even exit 0 is a failure)", state)
		}
		if _, lastErr = s.api("/api/status", "", nil); lastErr == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatalf("management startup timed out: %s; %s", s.state(), s.redact(fmt.Sprint(lastErr)))
}

func (s *server) stop() {
	s.t.Helper()
	s.mustDocker("stop", "--time", "10", s.container)
	if state := s.state(); state != "exited exit=0 oom=false" {
		s.t.Fatalf("test server did not stop gracefully: %s", state)
	}
}

type apiResponse struct {
	Status       string
	ErrorMessage string
	Token        string
	Response     json.RawMessage
}

func (s *server) api(path, token string, form url.Values) (apiResponse, error) {
	var result apiResponse
	// The official image includes curl. Execute only against its own loopback;
	// network=none means no published ports, host network, or external egress.
	// Curl configuration and credentials travel on stdin, never Docker argv.
	var config strings.Builder
	fmt.Fprintf(&config, "url = %q\nrequest = \"POST\"\nmax-time = 3\nfail\nsilent\nshow-error\nnoproxy = \"*\"\n", "http://127.0.0.1:5380"+path)
	fmt.Fprintf(&config, "header = %q\ndata = %q\n", "Content-Type: application/x-www-form-urlencoded", form.Encode())
	if token != "" {
		fmt.Fprintf(&config, "header = %q\n", "Authorization: Bearer "+token)
	}
	body, err := s.dockerInput(config.String(), "exec", "-i", s.container, "curl", "--config", "-")
	if err != nil {
		return result, err
	}
	if err := json.NewDecoder(io.LimitReader(strings.NewReader(body), 1<<20)).Decode(&result); err != nil {
		return result, fmt.Errorf("%s: invalid API response: %w", path, err)
	}
	if result.Status != "ok" {
		return result, fmt.Errorf("%s: API status %q: %s", path, result.Status, result.ErrorMessage)
	}
	return result, nil
}

func (s *server) mustAPI(path, token string, form url.Values) apiResponse {
	s.t.Helper()
	result, err := s.api(path, token, form)
	if err != nil {
		s.t.Fatal(s.redact(err.Error()))
	}
	return result
}

func (s *server) login(user, password string) string {
	s.t.Helper()
	result := s.mustAPI("/api/user/login", "", url.Values{"user": {user}, "pass": {password}})
	if result.Token == "" {
		s.t.Fatal("successful login returned no token")
	}
	s.secrets = append(s.secrets, result.Token)
	return result.Token
}

func (s *server) createZone(token, zone string, customACL bool) {
	s.t.Helper()
	s.mustAPI("/api/zones/create", token, url.Values{"zone": {zone}, "type": {"Primary"}})
	if customACL {
		s.mustAPI("/api/zones/permissions/set", token, url.Values{
			"zone": {zone}, "userPermissions": {fixtureUser + "|true|true|false"},
			"groupPermissions": {fixtureGroup + "|true|false|true"},
		})
		s.checkACL(token, zone, true)
	}
}

func (s *server) checkACL(token, zone string, customACL bool) {
	s.t.Helper()
	var acl struct {
		Section, SubItem string
		UserPermissions  []struct {
			Username                      string
			CanView, CanModify, CanDelete bool
		}
		GroupPermissions []struct {
			Name                          string
			CanView, CanModify, CanDelete bool
		}
	}
	result := s.mustAPI("/api/zones/permissions/get", token, url.Values{"zone": {zone}})
	if err := json.Unmarshal(result.Response, &acl); err != nil {
		s.t.Fatal(err)
	}
	if acl.Section != "Zones" || acl.SubItem != zone {
		s.t.Fatalf("unexpected permission response: section %q, zone %q", acl.Section, acl.SubItem)
	}
	users, groups := map[string]int{}, map[string]int{}
	for _, user := range acl.UserPermissions {
		users[user.Username] = flags(user.CanView, user.CanModify, user.CanDelete)
	}
	for _, group := range acl.GroupPermissions {
		groups[group.Name] = flags(group.CanView, group.CanModify, group.CanDelete)
	}
	wantUsers := map[string]int{}
	wantGroups := map[string]int{"Administrators": 7, "DNS Administrators": 7}
	if customACL {
		wantUsers[fixtureUser] = 3
		wantGroups[fixtureGroup] = 5
	}
	if !maps.Equal(groups, wantGroups) || !maps.Equal(users, wantUsers) {
		s.t.Fatalf("%s ACL: users=%v groups=%v; want users=%v groups=%v",
			zone, users, groups, wantUsers, wantGroups)
	}
}

func flags(view, modify, delete bool) int {
	var result int
	for i, enabled := range []bool{view, modify, delete} {
		if enabled {
			result |= 1 << i
		}
	}
	return result
}

// The API enforces full admin grants, so weaken only this synthetic leaf's flag.
// Format: Permission.WriteTo in DnsServerCore/Auth/Permission.cs (version 2).
func weakenDNSAdministrators(t *testing.T, auth []byte) {
	t.Helper()
	auth[dnsAdministratorsOffset(t, auth)] = 1
	t.Log("synthetic repair zone: downgraded only DNS Administrators from 7 to 1")
}

func dnsAdministratorsOffset(t *testing.T, auth []byte) int {
	t.Helper()
	needle := append([]byte{byte(len(repairedZone))}, []byte(repairedZone)...)
	if bytes.Count(auth, needle) != 1 {
		t.Fatal("expected exactly one serialized synthetic repair zone")
	}
	r := bytes.NewReader(auth[bytes.Index(auth, needle)+len(needle):])
	readByte := func() byte {
		value, err := r.ReadByte()
		if err != nil {
			t.Fatal("truncated synthetic permission:", err)
		}
		return value
	}
	readName := func() string {
		b := make([]byte, readByte())
		if _, err := io.ReadFull(r, b); err != nil {
			t.Fatal("truncated synthetic permission name:", err)
		}
		return string(b)
	}
	if readByte() != 2 || readByte() != 2 {
		t.Fatal("expected a version 2 Zones permission")
	}
	for count := int(readByte()); count > 0; count-- {
		readName()
		readByte()
	}
	found := 0
	foundOffset := -1
	for count := int(readByte()); count > 0; count-- {
		name := readName()
		offset := len(auth) - r.Len()
		flag := readByte()
		if strings.EqualFold(name, "DNS Administrators") {
			if flag != 7 {
				t.Fatalf("synthetic DNS Administrators precondition: got %d, want 7", flag)
			}
			foundOffset = offset
			found++
		}
	}
	var children uint32
	if err := binary.Read(r, binary.LittleEndian, &children); err != nil || children != 0 || found != 1 {
		t.Fatalf("expected one DNS Administrators grant in a leaf permission: matches=%d children=%d error=%v",
			found, children, err)
	}
	return foundOffset
}
