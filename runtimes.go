package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type runtimeVersion struct {
	Protocol string `json:"protocol"`
	Version  string `json:"version"`
	Family   string `json:"family,omitempty"`
}
type runtimeCapabilities struct {
	Runtimes         []runtimeVersion `json:"runtimes"`
	Protocols        []string         `json:"protocols"`
	CertificateModes []string         `json:"certificateModes"`
}

func (a *agent) runtimeCapabilities(ctx context.Context) runtimeCapabilities {
	c := runtimeCapabilities{Runtimes: []runtimeVersion{}, Protocols: []string{}, CertificateModes: []string{}}
	if !rootLinux() || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || !exists("/run/systemd/system") {
		return c
	}
	r, err := a.run(ctx, "systemctl", "--version")
	var v int
	_, _ = fmt.Sscanf(r.stdout, "systemd %d", &v)
	if err != nil || r.code != 0 || v < 247 {
		return c
	}
	c.Runtimes = []runtimeVersion{{"snell", "v5.0.1", "5"}, {"snell", "v6.0.0rc2", "6"}, {"shadowsocks", "1.14.3", ""}, {"trojan", "1.14.3", ""}, {"anytls", "1.14.3", ""}}
	c.Protocols = []string{"snell", "shadowsocks", "trojan", "anytls"}
	c.CertificateModes = []string{"self_signed"}
	if _, err := exec.LookPath("certbot"); err == nil {
		c.CertificateModes = append(c.CertificateModes, "acme")
	}
	return c
}

type snellRelease struct {
	version   string
	checksums map[string]string
}

var snellReleases = map[string]snellRelease{
	"5": {"v5.0.1", map[string]string{"amd64": "9bea1c2b9e35b73b31634856c04d18c393072b9e5dcde6a32781d8b8f908c539", "arm64": "2f178bf5ac468ce1a130454efa40a0603fbbe4e47ecc4880a989f4abc7f824cf"}},
	"6": {"v6.0.0rc2", map[string]string{"amd64": "8a9c4463ca87cfa5eaa37c6af0d37ab93ea275aa12391985bb2a375ca3abd7f2", "arm64": "a0b2915cbc77dc3baf8fa069e741c20808d8a10c3a8a93e709a0a580645c3bd7"}},
}

func unpackSnell(data []byte, checksum string) ([]byte, error) {
	hash := sha256.Sum256(data)
	if len(data) > 32*1024*1024 || hex.EncodeToString(hash[:]) != checksum {
		return nil, errors.New("download_failed")
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.New("download_failed")
	}
	for _, f := range archive.File {
		if f.Name != "snell-server" {
			continue
		}
		if !f.Mode().IsRegular() || f.UncompressedSize64 == 0 || f.UncompressedSize64 > 64*1024*1024 {
			break
		}
		r, err := f.Open()
		if err != nil {
			break
		}
		binary, err := io.ReadAll(io.LimitReader(r, 64*1024*1024+1))
		_ = r.Close()
		if err != nil || uint64(len(binary)) != f.UncompressedSize64 {
			break
		}
		return binary, nil
	}
	return nil, errors.New("download_failed")
}
func (a *agent) ensureRuntime(ctx context.Context, j job) (string, error) {
	if j.Protocol != "snell" {
		if j.RuntimeVersion != "1.14.3" {
			return "", errors.New("invalid_config")
		}
		if err := a.installRuntime(ctx); err != nil {
			return "", errors.New("download_failed")
		}
		return a.runtimeFile, nil
	}
	release, ok := snellReleases[j.Version]
	if !ok || j.RuntimeVersion != release.version || release.checksums[runtime.GOARCH] == "" {
		return "", errors.New("unsupported_host")
	}
	binary := filepath.Join(filepath.Dir(a.binaryFile), "snell-"+release.version, "snell-server")
	if err := safePath(binary); err != nil {
		return "", err
	}
	// Only our verified, versioned runtime path is eligible; system installations are never adopted.
	if exists(binary) {
		return binary, nil
	}
	arch := runtime.GOARCH
	if arch == "arm64" {
		arch = "aarch64"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://dl.nssurge.com/snell/snell-server-"+release.version+"-linux-"+arch+".zip", nil)
	if err != nil {
		return "", errors.New("download_failed")
	}
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 5 {
			return errors.New("download_failed")
		}
		return nil
	}}
	res, err := client.Do(req)
	if err != nil {
		return "", errors.New("download_failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", errors.New("download_failed")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 32*1024*1024+1))
	if err != nil {
		return "", errors.New("download_failed")
	}
	payload, err := unpackSnell(data, release.checksums[runtime.GOARCH])
	if err != nil {
		return "", err
	}
	if err = makeDirectory(filepath.Dir(binary), 0755); err != nil {
		return "", err
	}
	if err = atomicWrite(binary, payload, 0755); err != nil {
		return "", err
	}
	return binary, nil
}
