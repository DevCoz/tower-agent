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

	"time"
)

type config struct {
	URL   string `json:"url"`
	ID    string `json:"id"`
	Token string `json:"token"`
}
type serviceConfig struct {
	RuntimeVersion string             `json:"runtimeVersion"`
	Protocol       string             `json:"protocol"`
	Version        string             `json:"version,omitempty"`
	Certificate    *certificateConfig `json:"certificate,omitempty"`
	Port           int                `json:"port"`
	Password       string             `json:"password"`
	Method         string             `json:"method"`
	IPv6           bool               `json:"ipv6"`
}
type job struct {
	TaskID     string `json:"taskId"`
	ConfigHash string `json:"configHash"`
	serviceConfig
	ID       string         `json:"id"`
	Lease    string         `json:"lease"`
	Revision int            `json:"revision"`
	Action   string         `json:"action"`
	Previous *serviceConfig `json:"previous,omitempty"`
	Pending  *serviceConfig `json:"pending,omitempty"`
}
type report struct {
	CheckedAt      int64              `json:"checkedAt,omitempty"`
	TaskID         string             `json:"taskId"`
	ConfigHash     string             `json:"configHash"`
	Restored       bool               `json:"restored"`
	Revision       int                `json:"revision"`
	Implementation string             `json:"implementation,omitempty"`
	Certificate    *certificateReport `json:"certificate,omitempty"`
	ID             string             `json:"id"`
	Lease          string             `json:"lease"`
	Status         string             `json:"status"`
	Error          *string            `json:"error"`
}
type result struct {
	stdout string
	code   int
}
type agent struct {
	progress                                         func(context.Context, job, string)
	acknowledged                                     string
	base, units, configFile, binaryFile, runtimeFile string
	run                                              func(context.Context, ...string) (result, error)
	port                                             func(int, bool) error
	wait                                             func(context.Context, time.Duration) error
	client                                           *http.Client
	health                                           func(context.Context, job) error
	certificateChecks                                map[string]time.Time
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var tokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var binaryPattern = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)

func newAgent() *agent {
	a := &agent{base: "/var/lib/tower-panel/services", units: "/etc/systemd/system", configFile: "/etc/tower-agent/config.json", binaryFile: "/opt/tower-agent/tower-agent", runtimeFile: "/opt/tower-agent/sing-box-1.14.3/sing-box", run: runCommand, port: checkPort, wait: waitContext,
		client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	a.health = a.checkHealth
	return a
}

func runCommand(ctx context.Context, args ...string) (result, error) {
	limit := 20 * time.Second
	if filepath.Base(args[0]) == "certbot" {
		limit = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
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
	capabilities := a.runtimeCapabilities(ctx)
	binary := ""
	if len(capabilities.Protocols) > 0 {
		binary = a.runtimeFile
	}
	platform := "other"
	if runtime.GOOS == "linux" {
		platform = "linux"
	}
	payload := struct {
		Platform     string                   `json:"platform"`
		Capabilities runtimeCapabilities      `json:"capabilities"`
		Version      string                   `json:"version"`
		Protocol     int                      `json:"protocol"`
		Report       *report                  `json:"report,omitempty"`
		Certificates []certificateObservation `json:"certificates,omitempty"`
	}{platform, capabilities, version, 4, previous, nil}
	// Deliver a completed lease before running potentially slow certificate issuance.
	if previous == nil {
		payload.Certificates = a.renewCertificates(ctx)
	}
	var response struct {
		Job          *job   `json:"job"`
		Acknowledged string `json:"acknowledgedTaskId"`
	}
	err := a.request(ctx, c, "poll", payload, &response)
	if err != nil {
		return nil, binary, err
	}
	if response.Job != nil && (!uuidPattern.MatchString(response.Job.TaskID) || !tokenPattern.MatchString(response.Job.ConfigHash) || !uuidPattern.MatchString(response.Job.ID) || !tokenPattern.MatchString(response.Job.Lease) || response.Job.Revision < 1) {
		return nil, binary, errors.New("invalid_response")
	}
	a.acknowledged = response.Acknowledged
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
	pendingPath := filepath.Join(filepath.Dir(a.configFile), "pending-report.json")
	var pending *report
	if exists(pendingPath) {
		data, err := readFile(pendingPath)
		if err != nil {
			return err
		}
		if json.Unmarshal(data, &pending) != nil {
			return errors.New("invalid pending report")
		}
	}
	a.progress = func(ctx context.Context, j job, phase string) {
		var result struct{}
		_ = a.request(ctx, c, "progress", map[string]any{"id": j.ID, "taskId": j.TaskID, "revision": j.Revision, "lease": j.Lease, "phase": phase}, &result)
	}
	for ctx.Err() == nil {
		j, binary, err := a.poll(ctx, c, pending)
		if err == nil {
			if pending != nil && a.acknowledged == pending.TaskID {
				pending = nil
				if err := removeFile(pendingPath); err != nil {
					return err
				}
			}
			if j != nil && (pending == nil || j.TaskID == pending.TaskID) {
				pending = a.process(ctx, *j, binary)
				data, _ := json.Marshal(pending)
				if err := atomicWrite(pendingPath, data, 0600); err != nil {
					return err
				}
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
func (a *agent) executeJob(ctx context.Context, j job, binary string) *report {
	r := &report{TaskID: j.TaskID, ConfigHash: j.ConfigHash, ID: j.ID, Revision: j.Revision, Lease: j.Lease, Status: "active"}
	var err error
	switch j.Action {
	case "delete":
		err = a.deleteService(ctx, j)
		r.Status = "deleted"
	case "create", "update":
		if binary == "" {
			err = errors.New("unsupported_host")
		} else {
			if err = validateService(j.serviceConfig); err == nil {
				binary, err = a.ensureRuntime(ctx, j)
			}
			if err == nil {
				err = a.applyService(ctx, j, binary)
			}
			if err == nil {
				r.Implementation = j.RuntimeVersion
				if j.Protocol == "snell" {
					r.Implementation = "snell " + snellReleases[j.Version].version
				}
				if j.Certificate != nil {
					r.Certificate, err = a.inspectCertificate(j)
				}
			}
		}
	default:
		err = errors.New("invalid_config")
	}
	if err != nil {
		code := err.Error()
		switch code {
		case "state_conflict", "invalid_config", "port_in_use", "unsupported_host", "start_failed", "rollback_failed", "delete_failed", "certificate_failed", "download_failed":
		default:
			code = "internal_error"
		}
		r.Status = "failed"
		r.Error = &code
		if j.Action == "update" && j.Previous != nil && code != "rollback_failed" {
			previous := j
			previous.serviceConfig = *j.Previous
			healthCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 40*time.Second)
			r.Restored = a.previousHealthy(healthCtx, previous)
			cancel()
		}
	}
	if r.Status == "active" || r.Restored {
		r.CheckedAt = time.Now().Unix()
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
