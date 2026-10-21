package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var runtimeChecksums = map[string]string{
	"amd64": "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
	"arm64": "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e",
}

func unpackRuntime(data []byte, arch, checksum string) ([]byte, error) {
	hash := sha256.Sum256(data)
	if len(data) > 64*1024*1024 || hex.EncodeToString(hash[:]) != checksum {
		return nil, errors.New("sing-box checksum mismatch; runtime was not changed")
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("invalid sing-box archive")
	}
	defer gz.Close()
	archive := tar.NewReader(io.LimitReader(gz, 160*1024*1024))
	wanted := "sing-box-1.14.3-linux-" + arch + "/sing-box"
	for {
		entry, err := archive.Next()
		if err != nil {
			break
		}
		if entry.Name != wanted {
			continue
		}
		if entry.Typeflag != tar.TypeReg || entry.Size < 1 || entry.Size > 128*1024*1024 {
			break
		}
		binary, err := io.ReadAll(io.LimitReader(archive, entry.Size+1))
		if err != nil || int64(len(binary)) != entry.Size {
			break
		}
		return binary, nil
	}
	return nil, errors.New("invalid sing-box archive")
}
func (a *agent) installRuntime(ctx context.Context) error {
	if err := safePath(a.runtimeFile); err != nil {
		return err
	}
	checksum, ok := runtimeChecksums[runtime.GOARCH]
	if !ok {
		return errors.New("automatic sing-box installation supports Linux amd64/arm64")
	}
	if exists(a.runtimeFile) {
		v, err := a.run(ctx, a.runtimeFile, "version")
		if err == nil && v.code == 0 && strings.SplitN(v.stdout, "\n", 2)[0] == "sing-box version 1.14.3" {
			return nil
		}
	}
	fmt.Println("Downloading and verifying sing-box 1.14.3...")
	req, err := http.NewRequestWithContext(ctx, "GET", "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-"+runtime.GOARCH+".tar.gz", nil)
	if err != nil {
		return errors.New("cannot download sing-box")
	}
	// This unauthenticated client follows HTTPS release redirects only.
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" {
			return errors.New("invalid download redirect")
		}
		return nil
	}}
	res, err := client.Do(req)
	if err != nil {
		return errors.New("cannot download sing-box")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("cannot download sing-box")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 64*1024*1024+1))
	if err != nil {
		return errors.New("cannot download sing-box")
	}
	binary, err := unpackRuntime(data, runtime.GOARCH, checksum)
	if err != nil {
		return err
	}
	if err = makeDirectory(filepath.Dir(a.runtimeFile), 0755); err != nil {
		return err
	}
	candidate := a.runtimeFile + ".candidate"
	if err = atomicWrite(candidate, binary, 0755); err != nil {
		return err
	}
	defer os.Remove(candidate)
	v, err := a.run(ctx, candidate, "version")
	if err != nil || v.code != 0 || strings.SplitN(v.stdout, "\n", 2)[0] != "sing-box version 1.14.3" {
		return errors.New("unexpected sing-box version; runtime was not changed")
	}
	return os.Rename(candidate, a.runtimeFile)
}

func (a *agent) agentUnit() string {
	return fmt.Sprintf(`[Unit]
Description=Tower Linux Agent
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=%s run
Restart=always
RestartSec=15
TimeoutStopSec=50
UMask=0077
[Install]
WantedBy=multi-user.target
`, a.binaryFile)
}

type savedFile struct {
	path    string
	data    []byte
	mode    os.FileMode
	present bool
}

func saveFile(path string, limit int64) (savedFile, error) {
	s := savedFile{path: path}
	if err := safePath(path); err != nil {
		return s, err
	}
	if !exists(path) {
		return s, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return s, errors.New("unsupported_host")
	}
	s.data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(s.data)) > limit {
		return s, errors.New("unsupported_host")
	}
	s.mode = info.Mode().Perm()
	s.present = true
	return s, nil
}
func restoreFiles(files []savedFile) error {
	for _, f := range files {
		var err error
		if f.present {
			err = atomicWrite(f.path, f.data, f.mode)
		} else {
			err = removeFile(f.path)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (a *agent) verifyCredential(ctx context.Context, c config) error {
	if err := validateConfig(c); err != nil {
		return err
	}
	var response struct {
		OK bool `json:"ok"`
	}
	if a.request(ctx, c, "probe", struct{}{}, &response) != nil || !response.OK {
		return errors.New("Agent credential verification failed; configuration was not changed")
	}
	return nil
}
func (a *agent) install(ctx context.Context, origin, id string, withRuntime bool) error {
	if !rootLinux() {
		return errors.New("run the installer as root on Linux")
	}
	c := config{URL: strings.TrimRight(origin, "/"), ID: id, Token: strings.Repeat("0", 64)}
	if err := validateConfig(c); err != nil {
		return err
	}
	systemd, err := a.run(ctx, "systemctl", "--version")
	var systemdVersion int
	_, _ = fmt.Sscanf(systemd.stdout, "systemd %d", &systemdVersion)
	if err != nil || systemd.code != 0 || systemdVersion < 247 || !exists("/run/systemd/system") {
		return errors.New("a running systemd 247+ is required")
	}
	c.Token, err = readToken(ctx)
	if err != nil {
		return err
	}
	if err = a.verifyCredential(ctx, c); err != nil {
		return err
	}
	if err = makeDirectory(filepath.Dir(a.configFile), 0700); err != nil {
		return err
	}
	// Serialize installers separately from the running service's lock.
	unlockInstall, err := lockAgent(filepath.Join(filepath.Dir(a.configFile), "install.lock"), true)
	if err != nil {
		return err
	}
	defer unlockInstall()
	if withRuntime {
		if err = a.installRuntime(ctx); err != nil {
			return err
		}
	}
	if binary, _ := a.capabilities(ctx); binary == "" {
		return errors.New("install sing-box 1.14.3+ or use --install-sing-box")
	}
	if err = makeDirectory(filepath.Dir(a.binaryFile), 0755); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return errors.New("cannot locate Agent executable")
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return errors.New("cannot locate Agent executable")
	}
	payload, err := saveFile(self, 32*1024*1024)
	if err != nil || !payload.present {
		return errors.New("cannot read Agent executable")
	}
	return a.installFiles(ctx, c, payload.data)
}
func (a *agent) installFiles(ctx context.Context, c config, payload []byte) error {
	unitPath := filepath.Join(a.units, "tower-agent.service")
	files := []savedFile{}
	for _, path := range []string{a.configFile, a.binaryFile, unitPath} {
		limit := int64(65536)
		if path == a.binaryFile {
			limit = 32 * 1024 * 1024
		}
		s, err := saveFile(path, limit)
		if err != nil {
			return err
		}
		files = append(files, s)
	}
	wasActive := a.must(ctx, "systemctl", "is-active", "--quiet", "tower-agent.service") == nil
	wasEnabled := a.must(ctx, "systemctl", "is-enabled", "--quiet", "tower-agent.service") == nil
	if exists(unitPath) {
		if err := a.must(ctx, "systemctl", "stop", "tower-agent.service"); err != nil {
			return errors.New("cannot stop existing Agent")
		}
	}
	unlock, err := lockAgent(filepath.Join(filepath.Dir(a.configFile), "agent.lock"), true)
	if err != nil {
		if wasActive {
			_ = a.must(context.WithoutCancel(ctx), "systemctl", "start", "tower-agent.service")
		}
		return err
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()
	apply := func() error {
		data, _ := json.Marshal(c)
		if err := atomicWrite(a.configFile, append(data, '\n'), 0600); err != nil {
			return err
		}
		if err := atomicWrite(a.binaryFile, payload, 0700); err != nil {
			return err
		}
		if err := atomicWrite(unitPath, []byte(a.agentUnit()), 0644); err != nil {
			return err
		}
		if err := a.must(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := a.must(ctx, "systemctl", "enable", "tower-agent.service"); err != nil {
			return err
		}
		unlock()
		locked = false
		if err := a.must(ctx, "systemctl", "restart", "tower-agent.service"); err != nil {
			return err
		}
		if err := a.wait(ctx, 2*time.Second); err != nil {
			return err
		}
		return a.must(ctx, "systemctl", "is-active", "--quiet", "tower-agent.service")
	}
	if err = apply(); err != nil {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		defer cancel()
		_, stopErr := a.run(rctx, "systemctl", "stop", "tower-agent.service")
		if stopErr != nil {
			return errors.New("installation failed; could not stop Agent for rollback")
		}
		if !locked {
			unlock, err = lockAgent(filepath.Join(filepath.Dir(a.configFile), "agent.lock"), true)
			if err != nil {
				return errors.New("installation failed; Agent is still running")
			}
			locked = true
		}
		if err = restoreFiles(files); err != nil {
			return errors.New("installation failed; restoring Agent files failed")
		}
		if !wasEnabled {
			_, _ = a.run(rctx, "systemctl", "disable", "tower-agent.service")
		}
		if err = a.must(rctx, "systemctl", "daemon-reload"); err != nil {
			return errors.New("installation failed; reload the restored service")
		}
		unlock()
		locked = false
		if wasActive {
			if err = a.must(rctx, "systemctl", "start", "tower-agent.service"); err != nil {
				return errors.New("installation failed; restart the restored Agent service")
			}
		}
		return errors.New("installation failed; original Agent files restored")
	}
	fmt.Println("Tower Agent " + version + " installed. Check the Agents page for connection status.")
	return nil
}
