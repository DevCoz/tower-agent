package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type certificateConfig struct {
	Mode   string `json:"mode"`
	Domain string `json:"domain"`
	Email  string `json:"email,omitempty"`
}
type certificateReport struct {
	Domain      string `json:"domain"`
	ExpiresAt   int64  `json:"expiresAt"`
	Fingerprint string `json:"fingerprint"`
}
type certificateObservation struct {
	ID          string             `json:"id"`
	Certificate *certificateReport `json:"certificate"`
	Error       *string            `json:"error"`
}

var domainLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func validateCertificateConfig(c *certificateConfig) error {
	if c == nil || len(c.Domain) == 0 || len(c.Domain) > 253 || (c.Mode != "self_signed" && c.Mode != "acme") {
		return errors.New("invalid_config")
	}
	ip := net.ParseIP(c.Domain)
	if ip == nil {
		for _, label := range strings.Split(c.Domain, ".") {
			if !domainLabel.MatchString(label) {
				return errors.New("invalid_config")
			}
		}
	}
	if c.Mode == "acme" && (ip != nil || !strings.Contains(c.Domain, ".") || len(c.Email) > 254 || strings.ContainsAny(c.Email, "\r\n\x00")) {
		return errors.New("invalid_config")
	}
	return nil
}
func sameCertificate(a, b *certificateConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
func (a *agent) inspectCertificate(j job) (*certificateReport, error) {
	return a.certificateMetadata(j, true)
}
func (a *agent) certificateMetadata(j job, requireValid bool) (*certificateReport, error) {
	dir := filepath.Join(a.base, j.ID)
	cert, err := readFile(filepath.Join(dir, "certificate.pem"))
	if err != nil {
		return nil, errors.New("certificate_failed")
	}
	key, err := readFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, errors.New("certificate_failed")
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, errors.New("certificate_failed")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || j.Certificate == nil || leaf.VerifyHostname(j.Certificate.Domain) != nil || requireValid && (time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter)) {
		return nil, errors.New("certificate_failed")
	}
	hash := sha256.Sum256(leaf.Raw)
	return &certificateReport{j.Certificate.Domain, leaf.NotAfter.Unix(), hex.EncodeToString(hash[:])}, nil
}
func (a *agent) ensureCertificate(ctx context.Context, j job) error {
	if _, err := a.inspectCertificate(j); err == nil {
		return nil
	}
	// Never replace an existing TLS identity as a side effect of a config edit.
	dir := filepath.Join(a.base, j.ID)
	if exists(filepath.Join(dir, "key.pem")) || exists(filepath.Join(dir, "certificate.pem")) {
		return errors.New("certificate_failed")
	}
	return a.issueCertificate(ctx, j)
}
func (a *agent) issueCertificate(ctx context.Context, j job) error {
	if err := validateCertificateConfig(j.Certificate); err != nil {
		return err
	}
	dir := filepath.Join(a.base, j.ID)
	var cert, key []byte
	if j.Certificate.Mode == "self_signed" {
		// Reuse the existing private key during renewal.
		var private *ecdsa.PrivateKey
		if data, err := readFile(filepath.Join(dir, "key.pem")); err == nil {
			if block, _ := pem.Decode(data); block != nil {
				parsed, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
				private, _ = parsed.(*ecdsa.PrivateKey)
			}
		}
		var err error
		if private == nil {
			private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return errors.New("certificate_failed")
			}
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return errors.New("certificate_failed")
		}
		leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: j.Certificate.Domain}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if ip := net.ParseIP(j.Certificate.Domain); ip != nil {
			leaf.IPAddresses = []net.IP{ip}
		} else {
			leaf.DNSNames = []string{j.Certificate.Domain}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &private.PublicKey, private)
		if err != nil {
			return errors.New("certificate_failed")
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return errors.New("certificate_failed")
		}
		cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	} else {
		certbot, err := exec.LookPath("certbot")
		if err != nil {
			return errors.New("unsupported_host")
		}
		// Dedicated certbot account/renewal directory. No shared web-server or certificate hooks.
		root := filepath.Join(filepath.Dir(a.base), "acme", j.ID)
		if err = makeDirectory(root, 0700); err != nil {
			return err
		}
		args := []string{certbot, "certonly", "--standalone", "--non-interactive", "--agree-tos", "--preferred-challenges", "http", "--keep-until-expiring", "--cert-name", "service", "--config-dir", filepath.Join(root, "config"), "--work-dir", filepath.Join(root, "work"), "--logs-dir", filepath.Join(root, "logs"), "-d", j.Certificate.Domain}
		if j.Certificate.Email != "" {
			args = append(args, "--email", j.Certificate.Email)
		} else {
			args = append(args, "--register-unsafely-without-email")
		}
		if a.must(ctx, args...) != nil {
			return errors.New("certificate_failed")
		}
		readIssued := func(name string) ([]byte, error) {
			path, err := filepath.EvalSymlinks(filepath.Join(root, "config", "live", "service", name))
			if err != nil {
				return nil, err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
				return nil, errors.New("certificate_failed")
			}
			return readFile(path)
		}
		cert, err = readIssued("fullchain.pem")
		if err != nil {
			return errors.New("certificate_failed")
		}
		key, err = readIssued("privkey.pem")
		if err != nil {
			return errors.New("certificate_failed")
		}
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil || len(pair.Certificate) == 0 {
		return errors.New("certificate_failed")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(j.Certificate.Domain) != nil || !time.Now().Before(leaf.NotAfter) {
		return errors.New("certificate_failed")
	}
	savedCert, err := saveFile(filepath.Join(dir, "certificate.pem"), 65536)
	if err != nil {
		return err
	}
	savedKey, err := saveFile(filepath.Join(dir, "key.pem"), 65536)
	if err != nil {
		return err
	}
	if err = atomicWrite(filepath.Join(dir, "key.pem"), key, 0600); err != nil {
		return err
	}
	if err = atomicWrite(filepath.Join(dir, "certificate.pem"), cert, 0600); err != nil {
		_ = restoreFiles([]savedFile{savedCert, savedKey})
		return err
	}
	return nil
}
func (a *agent) checkHealth(ctx context.Context, j job) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(j.Port))
	if j.IPv6 {
		addr = net.JoinHostPort("::1", strconv.Itoa(j.Port))
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if j.Certificate == nil {
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return errors.New("start_failed")
		}
		_ = c.Close()
		return nil
	}
	expected, err := a.inspectCertificate(j)
	if err != nil {
		return err
	}
	// Local probe accepts self-signed chains but pins the exact validated certificate.
	td := tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: j.Certificate.Domain, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) == 0 {
			return errors.New("certificate_failed")
		}
		hash := sha256.Sum256(s.PeerCertificates[0].Raw)
		if hex.EncodeToString(hash[:]) != expected.Fingerprint {
			return errors.New("certificate_failed")
		}
		return nil
	}}}
	c, err := td.DialContext(ctx, "tcp", addr)
	if err != nil {
		return errors.New("certificate_failed")
	}
	_ = c.Close()
	return nil
}

func (a *agent) renewCertificates(ctx context.Context) []certificateObservation {
	if a.certificateChecks == nil {
		a.certificateChecks = map[string]time.Time{}
	}
	entries, err := os.ReadDir(a.base)
	if err != nil {
		return nil
	}
	observations := []certificateObservation{}
	for _, entry := range entries {
		if !entry.IsDir() || !uuidPattern.MatchString(entry.Name()) {
			continue
		}
		if time.Since(a.certificateChecks[entry.Name()]) < 6*time.Hour {
			continue
		}
		dir := filepath.Join(a.base, entry.Name())
		data, err := readFile(filepath.Join(dir, "service.json"))
		if err != nil {
			continue
		}
		j := job{ID: entry.Name()}
		if json.Unmarshal(data, &j.serviceConfig) != nil || validateService(j.serviceConfig) != nil || j.Certificate == nil {
			continue
		}
		d, err := a.define(j, a.runtimeFile)
		if err != nil {
			continue
		}
		if _, err = a.recordedUnit(j, d.unitPath); err != nil {
			continue
		}
		current, err := readFile(d.configPath)
		if err != nil || string(current) != d.config {
			continue
		}
		marked, err := applied(filepath.Join(dir, "applied.json"), d.config)
		if err != nil || !marked || a.must(ctx, "systemctl", "is-active", "--quiet", d.service) != nil {
			continue
		}
		report, err := a.certificateMetadata(j, false)
		if err != nil {
			continue
		}
		var failure *string
		a.certificateChecks[j.ID] = time.Now()
		if report.ExpiresAt < time.Now().Add(30*24*time.Hour).Unix() {
			cert, certErr := saveFile(filepath.Join(dir, "certificate.pem"), 65536)
			key, keyErr := saveFile(filepath.Join(dir, "key.pem"), 65536)
			if certErr != nil || keyErr != nil {
				continue
			}
			renewErr := a.issueCertificate(ctx, j)
			next, inspectErr := a.inspectCertificate(j)
			restarted := false
			if renewErr == nil && inspectErr == nil && next.Fingerprint != report.Fingerprint {
				restarted = true
				renewErr = a.must(ctx, "systemctl", "restart", d.service)
				if renewErr == nil {
					renewErr = a.wait(ctx, 2*time.Second)
				}
				if renewErr == nil {
					renewErr = a.health(ctx, j)
				}
			}
			if renewErr != nil || inspectErr != nil {
				code := "renewal_failed"
				failure = &code
				if restoreFiles([]savedFile{cert, key}) == nil && restarted {
					_ = a.must(context.WithoutCancel(ctx), "systemctl", "restart", d.service)
				}
			} else {
				report = next
			}
		}
		observations = append(observations, certificateObservation{j.ID, report, failure})
		// Bound each poll to one issuance so leases and other hosts remain responsive.
		break
	}
	return observations
}
