//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	// v1Image is the last release before the rewrite, for the upgrade test.
	v1Image = "nxtgenit/nxtfireguard-traffic-sensor:v1.0.5"
	// toolImage generates traffic (nc) from fixed addresses.
	toolImage = "busybox:1.36"
	// syslogPort is what the sensors listen on; 514 needs no extra
	// capability in a container, but a high port mirrors the README advice.
	syslogPort = 5514
)

// sensorImage is the image under test: E2E_IMAGE, or built by TestMain.
var sensorImage = "nfg-traffic-sensor:e2e"

func TestMain(m *testing.M) {
	if img := os.Getenv("E2E_IMAGE"); img != "" {
		sensorImage = img
	} else {
		fmt.Println("building", sensorImage)
		if out, err := run("docker", "build", "-t", sensorImage, ".."); err != nil {
			fmt.Println(out)
			os.Exit(1)
		}
	}
	for _, img := range []string{toolImage, v1Image} {
		if out, err := run("docker", "pull", "-q", img); err != nil {
			fmt.Println(out)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := run("docker", args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// eventually polls cond until it holds or timeout passes.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// retrying runs act, then polls cond, repeating act every interval until
// cond holds. For actions that may be ignored the first time, e.g. traffic
// sent while an update is still being applied.
func retrying(t *testing.T, timeout, interval time.Duration, what string, act func(), cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		act()
		next := time.Now().Add(interval)
		for time.Now().Before(next) {
			if cond() {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
	}
}

var netSeq atomic.Int32

// env is one test's private Docker network, with the fake backend on the
// host at the network's gateway address. Hosts on the network:
//
//	.1  gateway: the test process (backend, syslog sender)
//	.2  the sensor
//	.10 and up: traffic generators
type env struct {
	t       *testing.T
	id      string
	n       int32
	network string
	backend *backend
	port    int

	mu    sync.Mutex
	hosts map[int]string // generator containers by host number
}

func newEnv(t *testing.T) *env {
	t.Helper()
	n := 10 + netSeq.Add(1)
	e := &env{t: t, n: n, id: fmt.Sprintf("nfge2e-%d-%d", os.Getpid()%10000, n), hosts: map[int]string{}}
	e.network = e.id
	docker(t, "network", "create", "--subnet", e.ip(0)+"/24", "--gateway", e.ip(1), e.network)
	t.Cleanup(func() {
		e.mu.Lock()
		for _, c := range e.hosts {
			_, _ = run("docker", "rm", "-f", c)
		}
		e.mu.Unlock()
		_, _ = run("docker", "network", "rm", e.network)
	})
	e.backend = newBackend(t)
	return e
}

func (e *env) ip(host int) string { return fmt.Sprintf("10.231.%d.%d", e.n, host) }

func (e *env) sensorIP() string { return e.ip(2) }

func (e *env) backendURL(port int) string {
	return "http://" + net.JoinHostPort(e.ip(1), strconv.Itoa(port))
}

// startBackend serves the fake backend on any free port.
func (e *env) startBackend() {
	e.port = e.backend.start(":0")
}

// reservePort picks the port the backend will use later.
func (e *env) reservePort() {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		e.t.Fatal(err)
	}
	e.port = ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
}

func (e *env) volume() string {
	v := e.id + "-data"
	docker(e.t, "volume", "create", v)
	e.t.Cleanup(func() { _, _ = run("docker", "volume", "rm", "-f", v) })
	return v
}

type sensor struct {
	e    *env
	name string
}

// startSensor runs image as the sensor (.2) with the given environment on
// top of the usual one.
func (e *env) startSensor(image, volume string, extraEnv ...string) *sensor {
	e.t.Helper()
	name := fmt.Sprintf("%s-sensor-%d", e.id, time.Now().UnixNano()%100000)
	envs := []string{
		"TRAFFIC_SENSOR_NAME=" + sensorName,
		"AUTH_SECRET=" + authSecret,
		"HEARTBEAT_IDENTIFIER=" + heartbeatID,
		"NFG_ARBITER_URL=" + e.backendURL(e.port),
		"HEARTBEAT_URL=" + e.backendURL(e.port),
		"SYSLOG_PORT=" + strconv.Itoa(syslogPort),
		"DEBUG=true",
	}
	envs = append(envs, extraEnv...)
	args := []string{"run", "-d", "--name", name, "--network", e.network, "--ip", e.sensorIP(),
		"--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN"}
	if volume != "" {
		args = append(args, "-v", volume+":/data")
	}
	for _, kv := range envs {
		args = append(args, "-e", kv)
	}
	args = append(args, image)
	docker(e.t, args...)
	s := &sensor{e: e, name: name}
	e.t.Cleanup(func() { s.remove() })
	return s
}

func (s *sensor) logs() string {
	out, _ := run("docker", "logs", s.name)
	return out
}

// waitLog waits until the sensor has logged text.
func (s *sensor) waitLog(text string, timeout time.Duration) {
	s.e.t.Helper()
	eventually(s.e.t, timeout, "sensor log "+strconv.Quote(text), func() bool {
		return strings.Contains(s.logs(), text)
	})
}

// stop shuts the sensor down gracefully and removes it, keeping its volume.
func (s *sensor) stop() {
	s.e.t.Helper()
	docker(s.e.t, "stop", "-t", "20", s.name)
	s.remove()
}

func (s *sensor) remove() {
	if s.e.t.Failed() {
		if out := s.logs(); out != "" {
			s.e.t.Logf("logs of %s:\n%s", s.name, tail(out, 200))
		}
	}
	_, _ = run("docker", "rm", "-f", s.name)
}

// connect opens a TCP connection from generator host to the sensor. The port
// is closed, so the sensor answers with a reset; the SYN is what counts.
func (e *env) connect(host int) {
	e.t.Helper()
	c := e.generator(host)
	// nc fails on the reset; that is expected.
	_, _ = run("docker", "exec", c, "nc", "-w", "2", e.sensorIP(), "9")
}

func (e *env) generator(host int) string {
	e.t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.hosts[host]; ok {
		return c
	}
	c := fmt.Sprintf("%s-gen-%d", e.id, host)
	docker(e.t, "run", "-d", "--name", c, "--network", e.network, "--ip", e.ip(host), toolImage, "sleep", "3600")
	e.hosts[host] = c
	return c
}

func tail(s string, lines int) string {
	parts := bytes.Split([]byte(s), []byte("\n"))
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return string(bytes.Join(parts, []byte("\n")))
}
