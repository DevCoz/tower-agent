package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type config struct {
	URL   string `json:"url"`
	ID    string `json:"id"`
	Token string `json:"token"`
}
type instanceConfig struct {
	Port     int    `json:"port"`
	Password string `json:"password"`
	Method   string `json:"method"`
	IPv6     bool   `json:"ipv6"`
}
type job struct {
	instanceConfig
	ID       string          `json:"id"`
	Lease    string          `json:"lease"`
	Revision int             `json:"revision"`
	Action   string          `json:"action"`
	Previous *instanceConfig `json:"previous,omitempty"`
	Pending  *instanceConfig `json:"pending,omitempty"`
}
type report struct {
	ID     string  `json:"id"`
	Lease  string  `json:"lease"`
	Status string  `json:"status"`
	Error  *string `json:"error"`
}
type result struct {
	stdout string
	code   int
}
type agent struct {
	base, units, configFile, binaryFile, runtimeFile string
	run                                              func(context.Context, ...string) (result, error)
	port                                             func(int, bool) error
	wait                                             func(context.Context, time.Duration) error
	client                                           *http.Client
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var tokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var binaryPattern = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
var versionPattern = regexp.MustCompile(`^sing-box version (\d+)\.(\d+)\.(\d+)(?:\s|$)`)

func newAgent() *agent {
	return &agent{base: "/var/lib/tower-panel/instances", units: "/etc/systemd/system", configFile: "/etc/tower-agent/config.json", binaryFile: "/opt/tower-agent/tower-agent", runtimeFile: "/opt/tower-agent/sing-box-1.14.3/sing-box", run: runCommand, port: checkPort, wait: waitContext,
		client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func runCommand(ctx context.Context, args ...string) (result, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	// Never log command output: sing-box diagnostics can contain passwords.
	var output limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return result{output.String(), exit.ExitCode()}, nil
	}
	if err != nil {
		return result{}, errors.New("command_failed")
	}
	return result{output.String(), 0}, nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 8192 - b.Len(); remaining > 0 {
		_, _ = b.Buffer.Write(p[:min(remaining, len(p))])
	}
	return n, nil
}
func (a *agent) must(ctx context.Context, args ...string) error {
	r, err := a.run(ctx, args...)
	if err != nil || r.code != 0 {
		return errors.New("command_failed")
	}
	return nil
}
func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func supportsRuntime(line string) bool {
	m := versionPattern.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return major > 1 || major == 1 && (minor > 14 || minor == 14 && patch >= 3)
}
func (a *agent) capabilities(ctx context.Context) (string, *string) {
	if !rootLinux() {
		return "", nil
	}
	binary := a.runtimeFile
	if !exists(binary) {
		binary, _ = exec.LookPath("sing-box")
	}
	if binary == "" {
		return "", nil
	}
	binary, err := filepath.EvalSymlinks(binary)
	if err != nil {
		return "", nil
	}
	r, err := a.run(ctx, binary, "version")
	if err != nil || r.code != 0 {
		return "", nil
	}
	line := strings.SplitN(r.stdout, "\n", 2)[0]
	if len(line) > 80 {
		line = line[:80]
	}
	systemd, err := a.run(ctx, "systemctl", "--version")
	fields := strings.Fields(systemd.stdout)
	var systemdVersion int
	if len(fields) > 1 {
		systemdVersion, _ = strconv.Atoi(fields[1])
	}
	if err != nil || systemd.code != 0 || systemdVersion < 247 || !exists("/run/systemd/system") || !supportsRuntime(line) {
		return "", &line
	}
	return binary, &line
}

func validateConfig(c config) error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !uuidPattern.MatchString(c.ID) || !tokenPattern.MatchString(c.Token) {
		return errors.New("invalid Agent configuration; use an HTTPS origin, Agent UUID and token")
	}
	return nil
}
func (a *agent) request(ctx context.Context, c config, action string, payload, output any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("invalid_request")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.URL+"/api/agents/"+c.ID+"/"+action, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid_request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("User-Agent", "tower-agent/"+version)
	res, err := a.client.Do(req)
	if err != nil {
		return errors.New("connection_failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("connection_rejected")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(data) > 65536 || json.Unmarshal(data, output) != nil {
		return errors.New("invalid_response")
	}
	return nil
}
func (a *agent) poll(ctx context.Context, c config, previous *report) (*job, string, error) {
	binary, runtimeVersion := a.capabilities(ctx)
	payload := struct {
		Platform string  `json:"platform"`
		Capable  bool    `json:"capable"`
		Version  *string `json:"version"`
		Protocol int     `json:"protocol"`
		Report   *report `json:"report,omitempty"`
	}{runtime.GOOS, binary != "", runtimeVersion, 2, previous}
	var response struct {
		Job *job `json:"job"`
	}
	err := a.request(ctx, c, "poll", payload, &response)
	if err != nil {
		return nil, binary, err
	}
	if response.Job != nil && (!uuidPattern.MatchString(response.Job.ID) || !tokenPattern.MatchString(response.Job.Lease) || response.Job.Revision < 1) {
		return nil, binary, errors.New("invalid_response")
	}
	return response.Job, binary, nil
}
func (a *agent) serve(ctx context.Context) error {
	if !rootLinux() {
		return errors.New("run as root on Linux")
	}
	if err := safePath(a.configFile); err != nil {
		return err
	}
	unlock, err := lockAgent(filepath.Join(filepath.Dir(a.configFile), "agent.lock"), true)
	if err != nil {
		return err
	}
	defer unlock()
	data, err := readFile(a.configFile)
	if err != nil {
		return errors.New("cannot read Agent configuration; run install first")
	}
	var c config
	if json.Unmarshal(data, &c) != nil {
		return errors.New("invalid Agent configuration")
	}
	if err = validateConfig(c); err != nil {
		return err
	}
	var pending *report
	for ctx.Err() == nil {
		j, binary, err := a.poll(ctx, c, pending)
		if err == nil {
			pending = nil
			if j != nil {
				pending = a.process(ctx, *j, binary)
				continue
			}
		} else if ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "Tower Agent: connection failed; retrying")
		}
		if a.wait(ctx, 15*time.Second) != nil {
			break
		}
	}
	return nil
}
func (a *agent) process(ctx context.Context, j job, binary string) *report {
	r := &report{ID: j.ID, Lease: j.Lease, Status: "active"}
	var err error
	switch j.Action {
	case "delete":
		err = a.deleteInstance(ctx, j)
		r.Status = "deleted"
	case "create", "update":
		if binary == "" {
			err = errors.New("unsupported_host")
		} else {
			err = a.createInstance(ctx, j, binary)
		}
	default:
		err = errors.New("invalid_config")
	}
	if err != nil {
		code := err.Error()
		switch code {
		case "invalid_config", "port_in_use", "unsupported_host", "start_failed", "rollback_failed", "delete_failed":
		default:
			code = "internal_error"
		}
		r.Status = "failed"
		r.Error = &code
	}
	return r
}
func checkPort(port int, ipv6 bool) error {
	// The sing-box IPv6 wildcard also accepts IPv4 on typical Linux hosts.
	// Go's tcp6/udp6 sockets are IPv6-only, so check both families explicitly.
	if ipv6 {
		if err := checkPort(port, false); err != nil {
			return err
		}
	}
	host, tcp, udp := "0.0.0.0", "tcp4", "udp4"
	if ipv6 {
		host, tcp, udp = "::", "tcp6", "udp6"
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	l, err := net.Listen(tcp, address)
	if err != nil {
		return errors.New("port_in_use")
	}
	defer l.Close()
	p, err := net.ListenPacket(udp, address)
	if err != nil {
		return errors.New("port_in_use")
	}
	defer p.Close()
	return nil
}
