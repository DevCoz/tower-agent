package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func protocolJob(j job, protocol string) job {
	j.Protocol = protocol
	j.RuntimeVersion = "1.14.3"
	j.Method = ""
	j.Password = strings.Repeat("a", 32)
	j.Version = ""
	j.Certificate = nil
	switch protocol {
	case "shadowsocks":
		j.Method = "2022-blake3-aes-128-gcm"
		j.Password = "eHh4eHh4eHh4eHh4eHh4eA=="
	case "snell":
		j.Version = "6"
		j.RuntimeVersion = "v6.0.0rc2"
	default:
		j.Certificate = &certificateConfig{Mode: "self_signed", Domain: "node.test"}
	}
	return j
}
func TestAllProtocolLifecycle(t *testing.T) {
	for _, protocol := range []string{"snell", "shadowsocks", "trojan", "anytls"} {
		t.Run(protocol, func(t *testing.T) {
			a, f, base := fixture(t)
			j := protocolJob(base, protocol)
			d := provision(t, a, j)
			if !strings.HasPrefix(d.service, "tower-proxy-") || !strings.Contains(d.unit, "protocol 4") {
				t.Fatal("wrong ownership namespace")
			}
			if strings.Contains(d.unit, j.Password) {
				t.Fatal("unit leaked secret")
			}
			if protocol != "snell" {
				var config map[string]any
				requireNoError(t, json.Unmarshal([]byte(d.config), &config))
				inbound := config["inbounds"].([]any)[0].(map[string]any)
				if inbound["type"] != protocol {
					t.Fatal("wrong inbound")
				}
				if j.Certificate != nil {
					if inbound["tls"] == nil || inbound["users"] == nil {
						t.Fatal("missing TLS users")
					}
					_, err := a.inspectCertificate(j)
					requireNoError(t, err)
				}
			} else if !strings.Contains(d.config, "listen = [::]:") || !strings.Contains(d.unit, " -c %d/config") {
				t.Fatal("invalid Snell config")
			}
			f.calls = nil
			requireNoError(t, a.applyService(context.Background(), j, "/usr/bin/sing-box"))
			if len(f.calls) != 1 {
				t.Fatal("replay restarted service")
			}
			edit := j
			edit.Action = "update"
			edit.Previous = &j.serviceConfig
			edit.Port++
			requireNoError(t, a.applyService(context.Background(), edit, "/usr/bin/sing-box"))
			fail := edit
			fail.Previous = &edit.serviceConfig
			fail.Port++
			a.health = func(_ context.Context, j job) error {
				if j.Port == fail.Port {
					return errors.New("start_failed")
				}
				return nil
			}
			requireError(t, a.applyService(context.Background(), fail, "/usr/bin/sing-box"), "start_failed")
			current, _ := a.define(edit, "/usr/bin/sing-box")
			if read(t, current.configPath) != current.config || !f.active[d.service] {
				t.Fatal("rollback did not restore service")
			}
			edit.Action = "delete"
			requireNoError(t, a.deleteService(context.Background(), edit))
			requireNoError(t, a.deleteService(context.Background(), edit))
			if exists(d.directory) || exists(d.unitPath) {
				t.Fatal("uninstall left secrets or service")
			}
		})
	}
}
func TestProtocolValidationAndCertificateIdentity(t *testing.T) {
	a, _, base := fixture(t)
	for _, protocol := range []string{"", "vmess", "shell"} {
		j := base
		j.Protocol = protocol
		j.RuntimeVersion = "1.14.3"
		requireError(t, a.applyService(context.Background(), j, "/usr/bin/sing-box"), "invalid_config")
	}
	j := protocolJob(base, "trojan")
	provision(t, a, j)
	edit := j
	edit.Action = "update"
	edit.Previous = &j.serviceConfig
	edit.Certificate = &certificateConfig{Mode: "self_signed", Domain: "different.test"}
	requireError(t, a.applyService(context.Background(), edit, "/usr/bin/sing-box"), "invalid_config")
	for _, domain := range []string{"-bad.test", "node.test\n[Service]", "node.test/path", "node..test"} {
		edit := j
		edit.Certificate = &certificateConfig{Mode: "self_signed", Domain: domain}
		requireError(t, validateService(edit.serviceConfig), "invalid_config")
	}
}
func TestCertificateRenewalPreservesPrivateKey(t *testing.T) {
	a, _, base := fixture(t)
	j := protocolJob(base, "anytls")
	d := provision(t, a, j)
	before := read(t, filepath.Join(d.directory, "key.pem"))
	original, err := a.inspectCertificate(j)
	requireNoError(t, err)
	requireNoError(t, a.issueCertificate(context.Background(), j))
	current, err := a.inspectCertificate(j)
	requireNoError(t, err)
	if original.Fingerprint == current.Fingerprint || before != read(t, filepath.Join(d.directory, "key.pem")) {
		t.Fatal("renewal did not preserve private key")
	}
	wrong := j
	wrong.Certificate = &certificateConfig{Mode: "self_signed", Domain: "other.test"}
	_, err = a.inspectCertificate(wrong)
	requireError(t, err, "certificate_failed")
}
func TestSnellArchiveChecks(t *testing.T) {
	archive := func(name string, mode os.FileMode) []byte {
		var data bytes.Buffer
		z := zip.NewWriter(&data)
		h := &zip.FileHeader{Name: name}
		h.SetMode(mode)
		w, err := z.CreateHeader(h)
		requireNoError(t, err)
		_, err = w.Write([]byte("binary"))
		requireNoError(t, err)
		requireNoError(t, z.Close())
		return data.Bytes()
	}
	for _, entry := range []struct {
		name string
		mode os.FileMode
		ok   bool
	}{{"snell-server", 0755, true}, {"../snell-server", 0755, false}, {"snell-server", os.ModeSymlink | 0755, false}} {
		data := archive(entry.name, entry.mode)
		hash := sha256.Sum256(data)
		binary, err := unpackSnell(data, hex.EncodeToString(hash[:]))
		if entry.ok {
			requireNoError(t, err)
			if string(binary) != "binary" {
				t.Fatal("wrong payload")
			}
		} else {
			requireError(t, err, "download_failed")
		}
		_, err = unpackSnell(data, strings.Repeat("0", 64))
		requireError(t, err, "download_failed")
	}
}

func setCertificateExpiry(t *testing.T, dir string, expiry time.Time) {
	t.Helper()
	block, _ := pem.Decode([]byte(read(t, filepath.Join(dir, "key.pem"))))
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	requireNoError(t, err)
	key := parsed.(*ecdsa.PrivateKey)
	block, _ = pem.Decode([]byte(read(t, filepath.Join(dir, "certificate.pem"))))
	leaf, err := x509.ParseCertificate(block.Bytes)
	requireNoError(t, err)
	leaf.NotBefore = expiry.Add(-365 * 24 * time.Hour)
	leaf.NotAfter = expiry
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	requireNoError(t, err)
	requireNoError(t, atomicWrite(filepath.Join(dir, "certificate.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
}

func TestScheduledCertificateRenewal(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		expiry     time.Duration
		failHealth bool
	}{{"near_expiry", 15 * 24 * time.Hour, false}, {"expired_recovery", -time.Hour, false}, {"health_failure_rollback", 15 * 24 * time.Hour, true}} {
		t.Run(scenario.name, func(t *testing.T) {
			a, f, base := fixture(t)
			j := protocolJob(base, "trojan")
			d := provision(t, a, j)
			a.runtimeFile = "/usr/bin/sing-box"
			setCertificateExpiry(t, d.directory, time.Now().Add(scenario.expiry))
			beforeCert := read(t, filepath.Join(d.directory, "certificate.pem"))
			beforeKey := read(t, filepath.Join(d.directory, "key.pem"))
			before, err := a.certificateMetadata(j, false)
			requireNoError(t, err)
			if scenario.failHealth {
				a.health = func(context.Context, job) error { return errors.New("certificate_failed") }
			}
			f.calls = nil
			observations := a.renewCertificates(context.Background())
			if len(observations) != 1 || observations[0].ID != j.ID {
				t.Fatalf("missing certificate observation: %+v", observations)
			}
			restarts := 0
			for _, call := range f.calls {
				if len(call) > 1 && call[1] == "restart" {
					restarts++
				}
			}
			observation := observations[0]
			if scenario.failHealth {
				if observation.Error == nil || *observation.Error != "renewal_failed" || observation.Certificate.Fingerprint != before.Fingerprint || read(t, filepath.Join(d.directory, "certificate.pem")) != beforeCert || restarts != 2 {
					t.Fatal("failed renewal did not restore and report the original certificate")
				}
			} else if observation.Error != nil || observation.Certificate.Fingerprint == before.Fingerprint || observation.Certificate.ExpiresAt <= time.Now().Add(30*24*time.Hour).Unix() || restarts != 1 {
				t.Fatal("renewal did not activate a fresh certificate")
			}
			if beforeKey != read(t, filepath.Join(d.directory, "key.pem")) {
				t.Fatal("renewal changed private key")
			}
			if len(a.renewCertificates(context.Background())) != 0 {
				t.Fatal("certificate rechecked before the scheduled interval")
			}
		})
	}
}

func TestTLSHealthPinsServingCertificate(t *testing.T) {
	a, _, base := fixture(t)
	j := protocolJob(base, "anytls")
	d := provision(t, a, j)
	pair, err := tls.LoadX509KeyPair(filepath.Join(d.directory, "certificate.pem"), filepath.Join(d.directory, "key.pem"))
	requireNoError(t, err)
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	requireNoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	j.Port = listener.Addr().(*net.TCPAddr).Port
	j.IPv6 = false
	requireNoError(t, a.checkHealth(context.Background(), j))
	// The process still serves the previous certificate after the disk identity changes.
	requireNoError(t, a.issueCertificate(context.Background(), j))
	requireError(t, a.checkHealth(context.Background(), j), "certificate_failed")
}
