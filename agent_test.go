package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeSystem struct {
	a               *agent
	calls           [][]string
	active, enabled map[string]bool
	fail            func([]string) bool
}

func (f *fakeSystem) run(_ context.Context, args ...string) (result, error) {
	f.calls = append(f.calls, append([]string{}, args...))
	if f.fail != nil && f.fail(args) {
		return result{code: 1}, nil
	}
	if args[0] != "systemctl" {
		return result{stdout: "sing-box version 1.14.3\n"}, nil
	}
	service := args[len(args)-1]
	switch args[1] {
	case "--version":
		return result{stdout: "systemd 255\n"}, nil
	case "enable":
		f.enabled[service] = true
		if len(args) > 3 && args[2] == "--now" {
			f.active[service] = true
		}
	case "disable":
		f.enabled[service] = false
	case "start", "restart":
		f.active[service] = true
	case "stop":
		f.active[service] = false
	case "is-active":
		if !f.active[service] {
			return result{code: 3}, nil
		}
	case "is-enabled":
		if !f.enabled[service] {
			return result{code: 1}, nil
		}
	case "show":
		path := filepath.Join(f.a.units, args[2])
		if exists(path) {
			return result{stdout: path + "\n"}, nil
		}
	}
	return result{}, nil
}
func fixture(t *testing.T) (*agent, *fakeSystem, job) {
	t.Helper()
	root := t.TempDir()
	a := newAgent()
	a.base = filepath.Join(root, "instances")
	a.units = filepath.Join(root, "units")
	a.configFile = filepath.Join(root, "etc", "config.json")
	a.binaryFile = filepath.Join(root, "opt", "tower-agent")
	a.runtimeFile = filepath.Join(root, "runtime", "sing-box")
	for _, path := range []string{a.units, filepath.Dir(a.configFile), filepath.Dir(a.binaryFile)} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	f := &fakeSystem{a: a, active: map[string]bool{}, enabled: map[string]bool{}}
	a.run = f.run
	a.port = func(int, bool) error { return nil }
	a.wait = func(context.Context, time.Duration) error { return nil }
	j := job{ID: "11223344-5566-4788-99aa-bbccddeeff00", Lease: strings.Repeat("a", 64), Revision: 1, Action: "create", instanceConfig: instanceConfig{Port: 18388, Password: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 16)), Method: "2022-blake3-aes-128-gcm", IPv6: true}}
	return a, f, j
}
func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func requireError(t *testing.T, err error, expected string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected %s, got %v", expected, err)
	}
}
func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	requireNoError(t, err)
	return string(data)
}
func provision(t *testing.T, a *agent, j job) definition {
	t.Helper()
	requireNoError(t, a.createInstance(context.Background(), j, "/usr/bin/sing-box"))
	d, err := a.define(j, "/usr/bin/sing-box")
	requireNoError(t, err)
	return d
}

func TestIsolatedInstanceAndReplay(t *testing.T) {
	a, f, j := fixture(t)
	d := provision(t, a, j)
	unit := read(t, d.unitPath)
	for _, required := range []string{"DynamicUser=yes", "LoadCredential=config:", "ProtectSystem=strict", "CapabilityBoundingSet="} {
		if !strings.Contains(unit, required) {
			t.Fatalf("missing isolation %s", required)
		}
	}
	if strings.Contains(unit, j.Password) {
		t.Fatal("unit contains password")
	}
	if read(t, d.configPath) != d.config || !f.active[d.service] {
		t.Fatal("not provisioned")
	}
	f.calls = nil
	requireNoError(t, a.createInstance(context.Background(), j, "/usr/bin/sing-box"))
	if len(f.calls) != 1 || f.calls[0][1] != "is-active" {
		t.Fatalf("replay restarted: %v", f.calls)
	}
}
func TestInvalidJobsAndUnsupportedCiphers(t *testing.T) {
	a, _, valid := fixture(t)
	for _, mutate := range []func(*job){func(j *job) { j.ID = "../escape" }, func(j *job) { j.Port = 22 }, func(j *job) { j.Port = 65536 }, func(j *job) { j.Password = "wrong" }, func(j *job) { j.Method = "aes-128-gcm" }, func(j *job) { j.Method = "2022-blake3-chacha20-poly1305" }, func(j *job) { j.Password += "\n" }, func(j *job) { j.Action = "update" }} {
		j := valid
		mutate(&j)
		requireError(t, a.createInstance(context.Background(), j, "/usr/bin/sing-box"), "invalid_config")
	}
	for _, body := range []string{`{"port":true}`, `{"port":1.5}`, `{"ipv6":"true"}`} {
		var j job
		if json.Unmarshal([]byte(body), &j) == nil {
			t.Fatal("accepted malformed JSON")
		}
	}
	j := valid
	j.Method = "2022-blake3-aes-256-gcm"
	j.Password = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("y"), 32))
	_, err := a.define(j, "/usr/bin/sing-box")
	requireNoError(t, err)
	entries, err := os.ReadDir(a.units)
	requireNoError(t, err)
	if len(entries) != 0 {
		t.Fatal("invalid job wrote units")
	}
}
func TestValidationAndPortConflictPreserveRunningInstance(t *testing.T) {
	a, f, j := fixture(t)
	d := provision(t, a, j)
	original := read(t, d.configPath)
	edit := j
	edit.Action = "update"
	edit.Previous = &j.instanceConfig
	edit.Port++
	f.fail = func(args []string) bool { return len(args) > 1 && args[1] == "check" }
	requireError(t, a.createInstance(context.Background(), edit, "/usr/bin/sing-box"), "invalid_config")
	f.fail = nil
	a.port = func(int, bool) error { return errors.New("port_in_use") }
	requireError(t, a.createInstance(context.Background(), edit, "/usr/bin/sing-box"), "port_in_use")
	if !f.active[d.service] || read(t, d.configPath) != original {
		t.Fatal("validation disrupted original instance")
	}
}
func TestUpdateReplayAndRollback(t *testing.T) {
	a, f, j := fixture(t)
	d := provision(t, a, j)
	original := read(t, d.configPath)
	edit := j
	edit.Action = "update"
	edit.Previous = &j.instanceConfig
	edit.Port++
	edit.Method = "2022-blake3-aes-256-gcm"
	edit.Password = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("y"), 32))
	f.fail = func(args []string) bool { return args[1] == "enable" }
	requireError(t, a.createInstance(context.Background(), edit, "/usr/bin/sing-box"), "start_failed")
	if read(t, d.configPath) != original || !f.active[d.service] {
		t.Fatal("rollback did not restore original")
	}
	f.fail = func(args []string) bool { return args[1] == "enable" || args[1] == "start" }
	requireError(t, a.createInstance(context.Background(), edit, "/usr/bin/sing-box"), "rollback_failed")
	f.fail = nil
	requireNoError(t, a.createInstance(context.Background(), edit, "/usr/bin/sing-box"))
	if !strings.Contains(read(t, d.configPath), edit.Password) {
		t.Fatal("new key missing")
	}
	f.calls = nil
	requireNoError(t, a.createInstance(context.Background(), edit, "/usr/bin/sing-box"))
	if len(f.calls) != 1 {
		t.Fatal("update replay restarted service")
	}
}
func TestFailedCreateOnlyRemovesOwnedUnit(t *testing.T) {
	a, f, j := fixture(t)
	unrelated := filepath.Join(a.units, "unrelated.service")
	requireNoError(t, os.WriteFile(unrelated, []byte("keep"), 0644))
	f.fail = func(args []string) bool { return args[1] == "enable" }
	requireError(t, a.createInstance(context.Background(), j, "/usr/bin/sing-box"), "start_failed")
	entries, err := os.ReadDir(a.units)
	requireNoError(t, err)
	if len(entries) != 1 || read(t, unrelated) != "keep" {
		t.Fatal("removed unrelated file")
	}
}
func TestOwnershipAndSymlinkProtection(t *testing.T) {
	a, f, j := fixture(t)
	d, err := a.define(j, "/usr/bin/sing-box")
	requireNoError(t, err)
	requireNoError(t, os.WriteFile(d.unitPath, []byte("unrelated"), 0644))
	requireError(t, a.createInstance(context.Background(), j, "/usr/bin/sing-box"), "invalid_config")
	requireError(t, a.deleteInstance(context.Background(), j), "invalid_config")
	if len(f.calls) != 0 || read(t, d.unitPath) != "unrelated" {
		t.Fatal("touched unrelated service")
	}
	if runtime.GOOS == "windows" {
		return
	}
	requireNoError(t, os.Remove(d.unitPath))
	outside := t.TempDir()
	requireNoError(t, os.Symlink(outside, a.base))
	requireError(t, a.createInstance(context.Background(), j, "/usr/bin/sing-box"), "unsupported_host")
	entries, err := os.ReadDir(outside)
	requireNoError(t, err)
	if len(entries) != 0 {
		t.Fatal("followed symlink")
	}
}
func TestDeleteRequiresStopAndIsIdempotent(t *testing.T) {
	a, f, j := fixture(t)
	d := provision(t, a, j)
	f.fail = func(args []string) bool { return args[1] == "stop" }
	requireError(t, a.deleteInstance(context.Background(), j), "delete_failed")
	if !exists(d.unitPath) || !exists(d.configPath) {
		t.Fatal("deleted active instance")
	}
	f.fail = nil
	unrelated := filepath.Join(d.directory, "unrelated")
	requireNoError(t, os.WriteFile(unrelated, []byte("keep"), 0600))
	requireError(t, a.deleteInstance(context.Background(), j), "unsupported_host")
	requireNoError(t, os.Remove(unrelated))
	requireNoError(t, a.deleteInstance(context.Background(), j))
	requireNoError(t, a.deleteInstance(context.Background(), j))
	if exists(d.directory) || exists(d.unitPath) {
		t.Fatal("instance files remain")
	}
}
func TestDeletePendingConfigAndForeignFragment(t *testing.T) {
	a, f, j := fixture(t)
	d := provision(t, a, j)
	pending := j.instanceConfig
	pending.Port++
	j.Pending = &pending
	changed := j
	changed.instanceConfig = pending
	target, err := a.define(changed, "/usr/bin/sing-box")
	requireNoError(t, err)
	requireNoError(t, atomicWrite(d.configPath, []byte(target.config), 0600))
	a.run = func(ctx context.Context, args ...string) (result, error) {
		if args[1] == "show" {
			return result{stdout: "/some/other/unit"}, nil
		}
		return f.run(ctx, args...)
	}
	requireError(t, a.deleteInstance(context.Background(), j), "invalid_config")
	a.run = f.run
	requireNoError(t, a.deleteInstance(context.Background(), j))
}
func TestHTTPTokenVerificationAndRedirectRejection(t *testing.T) {
	a, _, j := fixture(t)
	var action string
	redirected := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected++; w.Write([]byte(`{"ok":true}`)) }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+j.Lease {
			t.Error("missing credential")
		}
		if action == "redirect" {
			http.Redirect(w, r, target.URL, 302)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/probe") {
			t.Error("installation reserved a job")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	a.client.Transport = server.Client().Transport
	c := config{server.URL, j.ID, j.Lease}
	requireNoError(t, a.verifyCredential(context.Background(), c))
	action = "redirect"
	requireError(t, a.verifyCredential(context.Background(), c), "verification failed")
	if redirected != 0 || exists(a.configFile) {
		t.Fatal("redirect followed or config written before verification")
	}
	for _, invalid := range []string{"http://panel.test", "https://user:secret@panel.test", "https://panel.test/path", "https://panel.test?query", "https://panel.test#fragment"} {
		c.URL = invalid
		requireError(t, validateConfig(c), "invalid Agent configuration")
	}
}
func TestPollReportsAndResponseValidation(t *testing.T) {
	a, _, j := fixture(t)
	mode := "job"
	calls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var input map[string]any
		requireNoError(t, json.NewDecoder(r.Body).Decode(&input))
		if input["protocol"] != float64(2) || input["report"].(map[string]any)["lease"] != j.Lease {
			t.Error("protocol/report changed")
		}
		switch mode {
		case "job":
			json.NewEncoder(w).Encode(map[string]any{"job": j})
		case "invalid":
			bad := j
			bad.ID = "../bad"
			json.NewEncoder(w).Encode(map[string]any{"job": bad})
		case "large":
			w.Write(bytes.Repeat([]byte("x"), 65537))
		case "denied":
			w.WriteHeader(401)
		}
	}))
	defer s.Close()
	a.client.Transport = s.Client().Transport
	c := config{s.URL, j.ID, j.Lease}
	previous := &report{ID: j.ID, Lease: j.Lease, Status: "active"}
	got, _, err := a.poll(context.Background(), c, previous)
	requireNoError(t, err)
	if got.ID != j.ID {
		t.Fatal("missing job")
	}
	for _, value := range []string{"invalid", "large", "denied"} {
		mode = value
		_, _, err = a.poll(context.Background(), c, previous)
		if err == nil {
			t.Fatal("accepted invalid response")
		}
	}
	if calls != 4 {
		t.Fatal("unexpected retries")
	}
}
func TestRuntimeVersionsAndArchiveValidation(t *testing.T) {
	for _, c := range []struct {
		version string
		valid   bool
	}{{"1.14.2", false}, {"1.14.3-beta.1", false}, {"1.14.3", true}, {"1.14.4", true}, {"1.15.0", true}} {
		if supportsRuntime("sing-box version "+c.version) != c.valid {
			t.Fatal(c.version)
		}
	}
	archive := func(kind byte) []byte {
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		tarball := tar.NewWriter(gz)
		size := int64(4)
		if kind != tar.TypeReg {
			size = 0
		}
		requireNoError(t, tarball.WriteHeader(&tar.Header{Name: "sing-box-1.14.3-linux-amd64/sing-box", Typeflag: kind, Size: size, Linkname: "/etc/passwd"}))
		if size > 0 {
			_, err := tarball.Write([]byte("test"))
			requireNoError(t, err)
		}
		requireNoError(t, tarball.Close())
		requireNoError(t, gz.Close())
		return out.Bytes()
	}
	for _, kind := range []byte{tar.TypeReg, tar.TypeSymlink} {
		data := archive(kind)
		hash := sha256.Sum256(data)
		checksum := hex.EncodeToString(hash[:])
		binary, err := unpackRuntime(data, "amd64", checksum)
		if kind == tar.TypeReg {
			requireNoError(t, err)
			if string(binary) != "test" {
				t.Fatal("wrong binary")
			}
		} else {
			requireError(t, err, "invalid sing-box archive")
		}
		_, err = unpackRuntime(data, "amd64", strings.Repeat("0", 64))
		requireError(t, err, "checksum mismatch")
	}
}
func TestPortConflictAndAtomicWrite(t *testing.T) {
	l, err := net.Listen("tcp4", "0.0.0.0:0")
	requireNoError(t, err)
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	requireError(t, checkPort(port, false), "port_in_use")
	path := filepath.Join(t.TempDir(), "config")
	requireNoError(t, atomicWrite(path, []byte("one"), 0600))
	requireNoError(t, atomicWrite(path, []byte("two"), 0600))
	if read(t, path) != "two" {
		t.Fatal("not replaced")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		requireNoError(t, err)
		if info.Mode().Perm() != 0600 {
			t.Fatal("config permissions")
		}
		link := path + "-link"
		requireNoError(t, os.Symlink(path, link))
		requireError(t, atomicWrite(link, []byte("bad"), 0600), "unsupported_host")
	}
}
func TestErrorReportDoesNotLeakCommandOutput(t *testing.T) {
	a, f, j := fixture(t)
	f.fail = func([]string) bool { return true }
	r := a.process(context.Background(), j, "/usr/bin/sing-box")
	if r.Error == nil || *r.Error != "invalid_config" {
		t.Fatal("wrong error")
	}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), j.Password) {
		t.Fatal("leaked password")
	}
	j.Action = "execute-shell"
	r = a.process(context.Background(), j, "/usr/bin/sing-box")
	if *r.Error != "invalid_config" {
		t.Fatal("unknown action accepted")
	}
}
