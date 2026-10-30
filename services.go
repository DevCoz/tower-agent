package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type definition struct{ directory, configPath, unitPath, service, config, unit string }

func validateService(c serviceConfig) error {
	if c.Port < 1024 || c.Port > 65535 {
		return errors.New("invalid_config")
	}
	switch c.Protocol {
	case "shadowsocks":
		size := 0
		switch c.Method {
		case "2022-blake3-aes-128-gcm":
			size = 16
		case "2022-blake3-aes-256-gcm":
			size = 32
		}
		key, err := base64.StdEncoding.Strict().DecodeString(c.Password)
		if size == 0 || err != nil || len(key) != size || base64.StdEncoding.EncodeToString(key) != c.Password {
			return errors.New("invalid_config")
		}
	case "snell", "trojan", "anytls":
		if !credentialPattern.MatchString(c.Password) || c.Method != "" {
			return errors.New("invalid_config")
		}
	default:
		return errors.New("invalid_config")
	}
	if c.Protocol == "snell" {
		if c.Version != "5" && c.Version != "6" {
			return errors.New("invalid_config")
		}
	} else if c.Version != "" {
		return errors.New("invalid_config")
	}
	tls := c.Protocol == "trojan" || c.Protocol == "anytls"
	if tls {
		return validateCertificateConfig(c.Certificate)
	}
	if c.Certificate != nil {
		return errors.New("invalid_config")
	}
	return nil
}

var credentialPattern = regexp.MustCompile(`^[A-Za-z0-9_+/=.-]{16,128}$`)

func (a *agent) define(j job, binary string) (definition, error) {
	d := definition{}
	if !uuidPattern.MatchString(j.ID) || !binaryPattern.MatchString(binary) {
		return d, errors.New("invalid_config")
	}
	if err := validateService(j.serviceConfig); err != nil {
		return d, err
	}
	d.directory = filepath.Join(a.base, j.ID)
	d.configPath = filepath.Join(d.directory, "config.json")
	d.service = "tower-proxy-" + j.ID + ".service"
	d.unitPath = filepath.Join(a.units, d.service)
	for _, path := range []string{d.configPath, d.unitPath} {
		if err := safePath(path); err != nil {
			return d, err
		}
	}
	listen := "0.0.0.0"
	if j.IPv6 {
		listen = "::"
	}
	command := binary + " run -c %d/config"
	credentials := ""
	if j.Protocol == "snell" {
		d.config = fmt.Sprintf("[snell-server]\nlisten = %s:%d\npsk = %s\nipv6 = %t\n", listen, j.Port, j.Password, j.IPv6)
		if j.IPv6 {
			d.config = strings.Replace(d.config, "listen = :::", "listen = [::]:", 1)
		}
		command = binary + " -c %d/config"
	} else {
		inbound := map[string]any{"type": j.Protocol, "tag": "proxy-in", "listen": listen, "listen_port": j.Port}
		if j.Protocol == "shadowsocks" {
			inbound["method"] = j.Method
			inbound["password"] = j.Password
		} else {
			inbound["users"] = []map[string]string{{"name": "tower", "password": j.Password}}
			inbound["tls"] = map[string]any{"enabled": true, "certificate_path": "/run/credentials/" + d.service + "/certificate", "key_path": "/run/credentials/" + d.service + "/key"}
			credentials = fmt.Sprintf("LoadCredential=certificate:%s\nLoadCredential=key:%s\n", filepath.Join(d.directory, "certificate.pem"), filepath.Join(d.directory, "key.pem"))
		}
		configuration := map[string]any{"log": map[string]string{"level": "warn"}, "inbounds": []any{inbound}, "outbounds": []any{map[string]string{"type": "direct", "tag": "direct"}}}
		encoded, _ := json.MarshalIndent(configuration, "", "  ")
		d.config = string(encoded) + "\n"
	}
	d.unit = fmt.Sprintf(`# Managed by Tower Agent protocol 4: %s
[Unit]
Description=Tower proxy service %s
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
DynamicUser=yes
LoadCredential=config:%s
%sExecStart=%s
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=
UMask=0077
[Install]
WantedBy=multi-user.target
`, j.ID, j.ID, d.configPath, credentials, command)
	return d, nil
}

var execLine = regexp.MustCompile(`(?m)^ExecStart=(/[A-Za-z0-9_./-]+)(?: run)? -c %d/config$`)

func (a *agent) recordedUnit(j job, path string) (string, error) {
	if !exists(path) {
		return "", nil
	}
	data, err := readFile(path)
	if err != nil {
		return "", err
	}
	match := execLine.FindStringSubmatch(string(data))
	if match == nil {
		return "", errors.New("invalid_config")
	}
	d, err := a.define(j, match[1])
	if err != nil {
		return "", err
	}
	if d.unit != string(data) {
		return "", errors.New("invalid_config")
	}
	return string(data), nil
}
func digest(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
func markApplied(path, data string) error { return atomicWrite(path, []byte(digest(data)), 0600) }
func applied(path, data string) (bool, error) {
	if err := safePath(path); err != nil {
		return false, err
	}
	if !exists(path) {
		return false, nil
	}
	content, err := readFile(path)
	return string(content) == digest(data), err
}

func (a *agent) applyService(parent context.Context, j job, binary string) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	d, err := a.define(j, binary)
	if err != nil {
		return err
	}
	previous := j
	if j.Action == "update" {
		if j.Previous == nil {
			return errors.New("invalid_config")
		}
		previous.serviceConfig = *j.Previous
		if previous.Protocol != j.Protocol || !sameCertificate(previous.Certificate, j.Certificate) {
			return errors.New("invalid_config")
		}
	} else if j.Action != "create" {
		return errors.New("invalid_config")
	}
	old, err := a.define(previous, binary)
	if err != nil {
		return err
	}
	oldUnit, err := a.recordedUnit(previous, d.unitPath)
	if err != nil {
		return err
	}
	current := ""
	if exists(d.configPath) {
		data, err := readFile(d.configPath)
		if err != nil {
			return err
		}
		current = string(data)
		if current != d.config && (j.Action != "update" || current != old.config) {
			return errors.New("invalid_config")
		}
	} else if oldUnit != "" {
		return errors.New("invalid_config")
	}
	marker := filepath.Join(d.directory, "applied.json")
	marked, err := applied(marker, d.config)
	if err != nil {
		return err
	}
	if oldUnit == d.unit && current == d.config && marked && a.must(ctx, "systemctl", "is-active", "--quiet", d.service) == nil {
		if err := a.health(ctx, j); err != nil {
			return err
		}
		return removeFile(filepath.Join(d.directory, "recovery.json"))
	}
	if err = makeDirectory(d.directory, 0700); err != nil {
		return err
	}
	if j.Certificate != nil {
		if err = a.ensureCertificate(ctx, j); err != nil {
			return err
		}
	}
	candidate := filepath.Join(d.directory, "candidate.json")
	checkConfig := d.config
	if j.Certificate != nil {
		checkConfig = strings.ReplaceAll(checkConfig, "/run/credentials/"+d.service+"/certificate", filepath.ToSlash(filepath.Join(d.directory, "certificate.pem")))
		checkConfig = strings.ReplaceAll(checkConfig, "/run/credentials/"+d.service+"/key", filepath.ToSlash(filepath.Join(d.directory, "key.pem")))
	}
	if err = atomicWrite(candidate, []byte(checkConfig), 0600); err != nil {
		return err
	}
	var checkErr error
	if j.Protocol != "snell" {
		checkErr = a.must(ctx, binary, "check", "-c", candidate)
	}
	if err = removeFile(candidate); err != nil {
		return err
	}
	if checkErr != nil {
		return errors.New("invalid_config")
	}
	if (oldUnit == "" || previous.Port != j.Port) && current != d.config {
		if err = a.port(j.Port, j.IPv6); err != nil {
			return err
		}
	}
	recoveryPath := filepath.Join(d.directory, "recovery.json")
	oldUnit, err = a.recoveryUnit(j, recoveryPath, oldUnit)
	if err != nil {
		return err
	}
	apply := func() error {
		if oldUnit != "" {
			if err := a.must(ctx, "systemctl", "stop", d.service); err != nil {
				return err
			}
			if err := a.port(j.Port, j.IPv6); err != nil {
				return err
			}
		}
		if err := atomicWrite(d.configPath, []byte(d.config), 0600); err != nil {
			return err
		}
		if err := atomicWrite(d.unitPath, []byte(d.unit), 0644); err != nil {
			return err
		}
		if err := a.must(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := a.must(ctx, "systemctl", "enable", "--now", d.service); err != nil {
			return err
		}
		if err := a.wait(ctx, 2*time.Second); err != nil {
			return err
		}
		if err := a.must(ctx, "systemctl", "is-active", "--quiet", d.service); err != nil {
			return err
		}
		if a.progress != nil {
			a.progress(ctx, j, "verifying")
		}
		if err := a.health(ctx, j); err != nil {
			return err
		}
		state, _ := json.Marshal(j.serviceConfig)
		if err := atomicWrite(filepath.Join(d.directory, "service.json"), state, 0600); err != nil {
			return err
		}
		return markApplied(marker, d.config)
	}
	if failure := apply(); failure != nil {
		if a.progress != nil {
			a.progress(context.WithoutCancel(parent), j, "rolling_back")
		}
		// Finish rollback even when the foreground operation was interrupted.
		rollbackCtx, rollbackCancel := context.WithTimeout(context.WithoutCancel(parent), 40*time.Second)
		defer rollbackCancel()
		if a.rollback(rollbackCtx, d, old.config, oldUnit, marker) != nil {
			return errors.New("rollback_failed")
		}
		if oldUnit != "" {
			if a.health(rollbackCtx, previous) != nil {
				return errors.New("rollback_failed")
			}
			state, _ := json.Marshal(previous.serviceConfig)
			if atomicWrite(filepath.Join(d.directory, "service.json"), state, 0600) != nil {
				return errors.New("rollback_failed")
			}
		}
		if err := removeFile(recoveryPath); err != nil {
			return errors.New("rollback_failed")
		}
		if failure.Error() == "port_in_use" {
			return failure
		}
		return errors.New("start_failed")
	}
	return removeFile(recoveryPath)
}
func (a *agent) rollback(ctx context.Context, d definition, oldConfig, oldUnit, marker string) error {
	if err := a.must(ctx, "systemctl", "stop", d.service); err != nil {
		return err
	}
	if oldUnit != "" {
		if err := atomicWrite(d.configPath, []byte(oldConfig), 0600); err != nil {
			return err
		}
		if err := atomicWrite(d.unitPath, []byte(oldUnit), 0644); err != nil {
			return err
		}
		if err := a.must(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := a.must(ctx, "systemctl", "start", d.service); err != nil {
			return err
		}
		if err := a.wait(ctx, 2*time.Second); err != nil {
			return err
		}
		if err := a.must(ctx, "systemctl", "is-active", "--quiet", d.service); err != nil {
			return err
		}
		return markApplied(marker, oldConfig)
	}
	if exists(d.unitPath) {
		if err := a.must(ctx, "systemctl", "disable", d.service); err != nil {
			return err
		}
		if err := removeFile(d.unitPath); err != nil {
			return err
		}
	}
	if err := removeFile(marker); err != nil {
		return err
	}
	return a.must(ctx, "systemctl", "daemon-reload")
}

func (a *agent) deleteService(parent context.Context, j job) error {
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	d, err := a.define(j, "/usr/bin/sing-box")
	if err != nil {
		return err
	}
	if _, err = a.recordedUnit(j, d.unitPath); err != nil {
		return err
	}
	allowed := []string{d.config}
	if j.Pending != nil {
		if j.Pending.Protocol != j.Protocol || !sameCertificate(j.Pending.Certificate, j.Certificate) {
			return errors.New("invalid_config")
		}
		pending := j
		pending.serviceConfig = *j.Pending
		p, err := a.define(pending, "/usr/bin/sing-box")
		if err != nil {
			return err
		}
		allowed = append(allowed, p.config)
	}
	if exists(d.configPath) {
		data, err := readFile(d.configPath)
		if err != nil {
			return err
		}
		matched := false
		for _, value := range allowed {
			if string(data) == value {
				matched = true
			}
		}
		if !matched {
			return errors.New("invalid_config")
		}
	}
	files := map[string]bool{"config.json": true, "candidate.json": true, "applied.json": true, "service.json": true, "certificate.pem": true, "key.pem": true, "recovery.json": true}
	if exists(d.directory) {
		entries, err := os.ReadDir(d.directory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil || !files[entry.Name()] || !info.Mode().IsRegular() {
				return errors.New("unsupported_host")
			}
		}
	}
	fragment, err := a.run(ctx, "systemctl", "show", d.service, "--property=FragmentPath", "--value")
	if err != nil {
		return errors.New("delete_failed")
	}
	if path := strings.TrimSpace(fragment.stdout); path != "" && path != d.unitPath {
		return errors.New("invalid_config")
	}
	stop, stopErr := a.run(ctx, "systemctl", "stop", d.service)
	state, stateErr := a.run(ctx, "systemctl", "is-active", "--quiet", d.service)
	if stopErr != nil || stateErr != nil || (state.code != 3 && state.code != 4) || stop.code != 0 && exists(d.unitPath) {
		return errors.New("delete_failed")
	}
	if exists(d.unitPath) {
		if err = a.must(ctx, "systemctl", "disable", d.service); err != nil {
			return errors.New("delete_failed")
		}
		if err = removeFile(d.unitPath); err != nil {
			return errors.New("delete_failed")
		}
	}
	if err = a.must(ctx, "systemctl", "daemon-reload"); err != nil {
		return errors.New("delete_failed")
	}
	for name := range files {
		if err = removeFile(filepath.Join(d.directory, name)); err != nil {
			return errors.New("delete_failed")
		}
	}
	acmeRoot := filepath.Join(filepath.Dir(a.base), "acme", j.ID)
	if err = safePath(acmeRoot); err != nil {
		return err
	}
	// os.RemoveAll removes links themselves; it does not follow certbot archive links.
	if err = os.RemoveAll(acmeRoot); err != nil {
		return errors.New("delete_failed")
	}
	if exists(d.directory) {
		if err = os.Remove(d.directory); err != nil {
			return errors.New("delete_failed")
		}
	}
	return nil
}
