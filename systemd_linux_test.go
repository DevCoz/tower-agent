//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Only opt in on an isolated Linux CI runner. Every service uses a random UUID.
func TestSystemdLifecycle(t *testing.T) {
	if os.Getenv("TOWER_SYSTEMD_TEST") != "1" {
		t.Skip("opt-in isolated Linux/systemd runner only")
	}
	if !rootLinux() || !exists("/run/systemd/system") {
		t.Fatal("root and running systemd required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var id [16]byte
	_, err := rand.Read(id[:])
	requireNoError(t, err)
	id[6] = id[6]&15 | 64
	id[8] = id[8]&63 | 128
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
	root := filepath.Join("/opt", "tower-agent-smoke-"+uuid)
	requireNoError(t, os.Mkdir(root, 0755))
	a := newAgent()
	a.base = filepath.Join(root, "instances")
	a.runtimeFile = filepath.Join(root, "runtime", "sing-box")
	j := job{ID: uuid, Action: "create", instanceConfig: instanceConfig{Port: freePort(t), Password: "eHh4eHh4eHh4eHh4eHh4eA==", Method: "2022-blake3-aes-128-gcm"}}
	service := "tower-sing-box-" + uuid + ".service"
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_, _ = runCommand(cleanupCtx, "systemctl", "stop", service)
		_, _ = runCommand(cleanupCtx, "systemctl", "disable", service)
		_ = os.Remove(filepath.Join(a.units, service))
		_, _ = runCommand(cleanupCtx, "systemctl", "daemon-reload")
		_ = os.RemoveAll(root)
	})
	requireNoError(t, a.installRuntime(ctx))
	if binary, _ := a.capabilities(ctx); binary == "" {
		t.Fatal("runtime capability gate failed")
	}
	requireNoError(t, a.createInstance(ctx, j, a.runtimeFile))
	assertListening(t, j.Port)
	requireNoError(t, a.createInstance(ctx, j, a.runtimeFile))
	edit := j
	edit.Action = "update"
	edit.Previous = &j.instanceConfig
	edit.Port = freePort(t)
	requireNoError(t, a.createInstance(ctx, edit, a.runtimeFile))
	assertListening(t, edit.Port)
	// Simulate a failed start command after writing a valid candidate; recovery
	// uses the real service manager, binary and config, not a fake process.
	failed := edit
	failed.Previous = &edit.instanceConfig
	failed.Port = freePort(t)
	a.run = func(ctx context.Context, args ...string) (result, error) {
		if len(args) > 1 && args[1] == "enable" {
			return result{code: 1}, nil
		}
		return runCommand(ctx, args...)
	}
	requireError(t, a.createInstance(ctx, failed, a.runtimeFile), "start_failed")
	assertListening(t, edit.Port)
	a.run = runCommand
	edit.Action = "delete"
	requireNoError(t, a.deleteInstance(ctx, edit))
	requireNoError(t, a.deleteInstance(ctx, edit))
	if exists(filepath.Join(a.base, j.ID)) || exists(filepath.Join(a.units, service)) {
		t.Fatal("delete left instance files")
	}
}
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	requireNoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	requireNoError(t, l.Close())
	return port
}
func assertListening(t *testing.T, port int) {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	requireNoError(t, err)
	requireNoError(t, c.Close())
}
