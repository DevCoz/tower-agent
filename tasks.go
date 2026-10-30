package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

// Keep the protocol 4 fixed-field digest identical to the control plane.
func serviceDigest(c serviceConfig) string {
	var certificate any
	if c.Certificate != nil {
		certificate = []any{c.Certificate.Mode, c.Certificate.Domain, c.Certificate.Email}
	}
	fields := []any{c.Protocol, c.Version, c.RuntimeVersion, c.Port, c.Password, c.Method, c.IPv6, certificate}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(fields)
	return digest(strings.TrimSuffix(encoded.String(), "\n"))
}

// A listening port alone does not prove the previous configuration was restored.
func (a *agent) previousHealthy(ctx context.Context, previous job) bool {
	state, err := readFile(filepath.Join(a.base, previous.ID, "service.json"))
	if err != nil {
		return false
	}
	var config serviceConfig
	if json.Unmarshal(state, &config) != nil {
		return false
	}
	actual, _ := json.Marshal(config)
	expected, _ := json.Marshal(previous.serviceConfig)
	if !bytes.Equal(actual, expected) {
		return false
	}
	unitPath := filepath.Join(a.units, "tower-proxy-"+previous.ID+".service")
	unit, err := a.recordedUnit(previous, unitPath)
	if err != nil || unit == "" {
		return false
	}
	match := execLine.FindStringSubmatch(unit)
	definition, err := a.define(previous, match[1])
	if err != nil {
		return false
	}
	current, err := readFile(definition.configPath)
	return err == nil && string(current) == definition.config && a.health(ctx, previous) == nil
}

type taskReceipt struct {
	TaskID     string  `json:"taskId"`
	NodeID     string  `json:"nodeId"`
	Revision   int     `json:"revision"`
	ConfigHash string  `json:"configHash"`
	InputHash  string  `json:"inputHash"`
	Result     *report `json:"result,omitempty"`
}

func (a *agent) process(ctx context.Context, j job, binary string) *report {
	fail := func() *report {
		code := "state_conflict"
		return &report{TaskID: j.TaskID, ID: j.ID, Revision: j.Revision, Lease: j.Lease, ConfigHash: j.ConfigHash, Status: "failed", Error: &code}
	}
	if !uuidPattern.MatchString(j.TaskID) || !uuidPattern.MatchString(j.ID) || !tokenPattern.MatchString(j.ConfigHash) || j.ConfigHash != serviceDigest(j.serviceConfig) || j.Revision < 1 {
		return fail()
	}
	normalized := j
	normalized.Lease = ""
	input, _ := json.Marshal(normalized)
	directory := filepath.Join(filepath.Dir(a.configFile), "tasks")
	if makeDirectory(directory, 0700) != nil {
		return fail()
	}
	path := filepath.Join(directory, j.TaskID+".json")
	highwater := filepath.Join(directory, "node-"+j.ID+".json")
	var receipt taskReceipt
	if exists(highwater) {
		data, err := readFile(highwater)
		if err != nil || json.Unmarshal(data, &receipt) != nil || receipt.Revision > j.Revision || receipt.Revision == j.Revision && receipt.TaskID != j.TaskID {
			return fail()
		}
	}
	if exists(path) {
		data, err := readFile(path)
		if err != nil || json.Unmarshal(data, &receipt) != nil || receipt.InputHash != digest(string(input)) || receipt.NodeID != j.ID {
			return fail()
		}
		if receipt.Result != nil {
			result := *receipt.Result
			result.Lease = j.Lease
			return &result
		}
	}
	receipt = taskReceipt{TaskID: j.TaskID, NodeID: j.ID, Revision: j.Revision, ConfigHash: j.ConfigHash, InputHash: digest(string(input))}
	data, _ := json.Marshal(receipt)
	if atomicWrite(path, data, 0600) != nil || atomicWrite(highwater, data, 0600) != nil {
		return fail()
	}
	if a.progress != nil {
		a.progress(ctx, j, "running")
	}
	result := a.executeJob(ctx, j, binary)
	receipt.Result = result
	data, _ = json.Marshal(receipt)
	if atomicWrite(path, data, 0600) != nil {
		return fail()
	}
	return result
}

type recoveryPoint struct {
	TaskID     string `json:"taskId"`
	ConfigHash string `json:"configHash"`
	Unit       string `json:"unit"`
}

func (a *agent) recoveryUnit(j job, path, original string) (string, error) {
	if exists(path) {
		data, err := readFile(path)
		var point recoveryPoint
		if err != nil || json.Unmarshal(data, &point) != nil || point.TaskID != j.TaskID || point.ConfigHash != j.ConfigHash {
			return "", errors.New("state_conflict")
		}
		return point.Unit, nil
	}
	data, _ := json.Marshal(recoveryPoint{j.TaskID, j.ConfigHash, original})
	if err := atomicWrite(path, data, 0600); err != nil {
		return "", err
	}
	return original, nil
}
