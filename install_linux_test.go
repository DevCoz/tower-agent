//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	unlock, err := lockAgent(path, true)
	requireNoError(t, err)
	_, err = lockAgent(path, true)
	requireError(t, err, "another Agent")
	unlock()
	next, err := lockAgent(path, true)
	requireNoError(t, err)
	next()
}
func TestInstallationRollbackAndSuccessfulReplacement(t *testing.T) {
	a, f, j := fixture(t)
	c := config{"https://panel.test", j.ID, j.Lease}
	unit := filepath.Join(a.units, "tower-agent.service")
	for path, data := range map[string]string{a.configFile: "original-config", a.binaryFile: "original-binary", unit: "original-unit"} {
		requireNoError(t, os.WriteFile(path, []byte(data), 0600))
	}
	f.active["tower-agent.service"] = true
	f.enabled["tower-agent.service"] = true
	f.fail = func(args []string) bool { return args[1] == "restart" }
	requireError(t, a.installFiles(context.Background(), c, []byte("new-binary")), "original Agent files restored")
	if read(t, a.configFile) != "original-config" || read(t, a.binaryFile) != "original-binary" || read(t, unit) != "original-unit" || !f.active["tower-agent.service"] {
		t.Fatal("installation rollback lost original state")
	}
	f.fail = nil
	requireNoError(t, a.installFiles(context.Background(), c, []byte("new-binary")))
	if read(t, a.binaryFile) != "new-binary" || !strings.Contains(read(t, a.configFile), c.Token) || !f.active["tower-agent.service"] {
		t.Fatal("installation incomplete")
	}
}
func TestFreshInstallFailureRemovesFiles(t *testing.T) {
	a, f, j := fixture(t)
	f.fail = func(args []string) bool { return args[1] == "restart" }
	requireError(t, a.installFiles(context.Background(), config{"https://panel.test", j.ID, j.Lease}, []byte("new")), "original Agent files restored")
	if exists(a.configFile) || exists(a.binaryFile) || exists(filepath.Join(a.units, "tower-agent.service")) || f.enabled["tower-agent.service"] {
		t.Fatal("partial installation left behind")
	}
}
