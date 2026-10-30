package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDurableReceiptReplaysWithoutHostMutation(t *testing.T) {
	a, f, j := fixture(t)
	j.Action = "delete"
	result := a.process(context.Background(), j, "")
	if result.Status != "deleted" {
		t.Fatalf("delete: %+v", result)
	}
	f.calls = nil
	restarted := newAgent()
	restarted.configFile = a.configFile
	j.Lease = strings.Repeat("b", 64)
	repeated := restarted.process(context.Background(), j, "")
	if repeated.Status != "deleted" || repeated.Lease != j.Lease {
		t.Fatalf("receipt not restored: %+v", repeated)
	}
	if len(f.calls) != 0 {
		t.Fatal("replay mutated host")
	}
	data := read(t, filepath.Join(filepath.Dir(a.configFile), "tasks", j.TaskID+".json"))
	if strings.Contains(data, j.Password) {
		t.Fatal("receipt leaked password")
	}
	changed := j
	changed.Port++
	if *a.process(context.Background(), changed, "").Error != "state_conflict" {
		t.Fatal("modified replay accepted")
	}
	newer := j
	newer.Revision++
	newer.TaskID = "31223344-5566-4788-99aa-bbccddeeff00"
	if a.process(context.Background(), newer, "").Status != "deleted" {
		t.Fatal("new revision failed")
	}
	if *a.process(context.Background(), j, "").Error != "state_conflict" {
		t.Fatal("stale revision accepted")
	}
}

func TestServiceDigestMatchesProtocol4ControlPlane(t *testing.T) {
	c := serviceConfig{Protocol: "trojan", RuntimeVersion: "1.14.3", Port: 9443, Password: "0123456789abcdef", Certificate: &certificateConfig{Mode: "acme", Domain: "node.test", Email: "ops+test@example.com"}}
	if serviceDigest(c) != "a198d272e4cf68fe6e8f4913373367681b35f72f109ae7b7c59fe4b04ca2d47a" {
		t.Fatal("Agent digest differs from the control plane")
	}
	a, f, j := fixture(t)
	j.Port++
	r := a.process(context.Background(), j, "/usr/bin/sing-box")
	if r.Error == nil || *r.Error != "state_conflict" || len(f.calls) != 0 {
		t.Fatal("changed configuration was not rejected before touching the host")
	}
}

func TestInterruptedUpdatePreservesOriginalRecoveryPoint(t *testing.T) {
	a, f, j := fixture(t)
	d := provision(t, a, j)
	edit := j
	edit.TaskID = "31223344-5566-4788-99aa-bbccddeeff00"
	edit.Revision = 2
	edit.Action = "update"
	edit.Previous = &j.serviceConfig
	edit.Port++
	candidate, err := a.define(edit, "/usr/bin/sing-box")
	requireNoError(t, err)
	// Crash after replacing configuration/unit but before health/receipt commit.
	recovery, _ := json.Marshal(recoveryPoint{edit.TaskID, edit.ConfigHash, d.unit})
	requireNoError(t, atomicWrite(filepath.Join(d.directory, "recovery.json"), recovery, 0600))
	requireNoError(t, atomicWrite(d.configPath, []byte(candidate.config), 0600))
	f.fail = func(args []string) bool { return len(args) > 1 && args[1] == "enable" }
	requireError(t, a.applyService(context.Background(), edit, "/usr/bin/sing-box"), "start_failed")
	if read(t, d.configPath) != d.config || read(t, d.unitPath) != d.unit {
		t.Fatal("original state was not restored")
	}
	if _, err = os.Stat(filepath.Join(d.directory, "recovery.json")); !os.IsNotExist(err) {
		t.Fatal("recovery marker retained after confirmed restore")
	}
}
