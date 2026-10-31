// Copyright (c) 2026 Seed contributors
//
// SPDX-License-Identifier: Apache-2.0
//

// Shim-owned swtpm (seed).
//
// When a sandbox carries the seed.loom.farm/tpm-mode annotation, the Kata
// shim owns exactly one swtpm process for that sandbox, the same way it owns
// virtiofsd. Everything below happens before cloud-hypervisor starts:
//
//  1. Sentinel: the file at swtpm_sentinel_path must contain the expected
//     Ceph fsid. This proves the shared TPM state filesystem is mounted, so a
//     missing state dir can never be mistaken for "no TPM yet".
//  2. Lock: an exclusive flock on <state-dir>/.session-lock, waited for up to
//     swtpm_lock_timeout. CephFS enforces flock across clients, so at most one
//     swtpm in the cluster runs against a given TPM state. The lock fd is
//     shared with the swtpm child, so the lock is only released once both the
//     shim has let go of it and swtpm has exited.
//  3. swtpm is started in socket mode with the seed:// backend. Only create
//     mode passes SWTPM_SEED_ALLOW_CREATE=1 (the backend refuses to manufacture
//     a TPM otherwise). swtpm gets Pdeathsig and its own process group.
//  4. Fingerprint: the shim speaks the swtpm control protocol and raw TPM 2.0
//     commands to derive the owner-hierarchy SRK and hashes its public area
//     (see srkTemplate / fingerprintFromPublic for the exact bytes).
//  5. create: the fingerprint is written to <state-dir>/tpm-fingerprint.
//     verify: it must equal the seed.loom.farm/tpm-fingerprint annotation.
//  6. The data channel is closed and cloud-hypervisor attaches to the same
//     control socket. CLH issues CMD_STOP + CMD_INIT itself, which power
//     cycles the TPM (swtpm sends TPM2_Shutdown(CLEAR) before stopping), so
//     the guest sees a freshly powered-on TPM and does its own TPM2_Startup.
//  7. Teardown: SIGTERM (SIGKILL fallback) to swtpm, then the lock is
//     released and the per-sandbox volatile dir and socket are removed.

package virtcontainers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	SeedTpmModeCreate = "create"
	SeedTpmModeVerify = "verify"

	DefaultSwtpmSentinelPath = "/var/lib/seed-controller/tpm/.seed-fs"
	DefaultSwtpmLockTimeout  = 120 // seconds

	swtpmSocketName      = "swtpm.sock"
	swtpmVolatileDirName = "swtpm-volatile"
	swtpmSessionLockName = ".session-lock"
	swtpmPermallName     = "tpm2-00.permall"
	swtpmFingerprintName = "tpm-fingerprint"
)

var (
	// Variables so unit tests can shorten them.
	swtpmSocketWaitTimeout = 10 * time.Second
	swtpmIOTimeout         = 30 * time.Second
	swtpmStopTimeout       = 10 * time.Second
	swtpmLockPollInterval  = 250 * time.Millisecond
)

// swtpmConfig is everything needed to run one sandbox's swtpm.
type swtpmConfig struct {
	// From the Kata configuration file.
	path         string
	sentinelPath string
	expectedFsid string
	lockTimeout  time.Duration

	// From the sandbox annotations.
	mode        string
	stateDir    string
	fingerprint string

	// Per-sandbox, local (under the sandbox's runtime dir).
	socketPath  string
	volatileDir string
}

// newSwtpmConfig builds the swtpm config for a sandbox from its hypervisor
// config. vmDir is the sandbox runtime dir (e.g. /run/vc/vm/<sandbox-id>).
func newSwtpmConfig(hc *HypervisorConfig, vmDir string) swtpmConfig {
	sentinel := hc.SwtpmSentinelPath
	if sentinel == "" {
		sentinel = DefaultSwtpmSentinelPath
	}
	timeout := hc.SwtpmLockTimeout
	if timeout == 0 {
		timeout = DefaultSwtpmLockTimeout
	}
	return swtpmConfig{
		path:         hc.SwtpmPath,
		sentinelPath: sentinel,
		expectedFsid: hc.SwtpmExpectedFsid,
		lockTimeout:  time.Duration(timeout) * time.Second,
		mode:         hc.SeedTpmMode,
		stateDir:     hc.SeedTpmStateDir,
		fingerprint:  hc.SeedTpmFingerprint,
		socketPath:   filepath.Join(vmDir, swtpmSocketName),
		volatileDir:  filepath.Join(vmDir, swtpmVolatileDirName),
	}
}

func (c *swtpmConfig) validate() error {
	if c.mode != SeedTpmModeCreate && c.mode != SeedTpmModeVerify {
		return fmt.Errorf("seed tpm: invalid tpm-mode %q (want %q or %q)", c.mode, SeedTpmModeCreate, SeedTpmModeVerify)
	}
	if c.path == "" {
		return errors.New("seed tpm: swtpm_path is not set in the Kata configuration")
	}
	if c.expectedFsid == "" {
		return errors.New("seed tpm: swtpm_expected_fsid is not set in the Kata configuration")
	}
	if !filepath.IsAbs(c.sentinelPath) {
		return fmt.Errorf("seed tpm: swtpm_sentinel_path %q is not absolute", c.sentinelPath)
	}
	if !filepath.IsAbs(c.stateDir) || filepath.Clean(c.stateDir) != c.stateDir {
		return fmt.Errorf("seed tpm: tpm-state-dir %q must be a clean absolute path", c.stateDir)
	}
	// The state dir must live below the directory that holds the sentinel,
	// i.e. on the filesystem the sentinel vouches for.
	root := filepath.Dir(c.sentinelPath)
	if !strings.HasPrefix(c.stateDir, root+string(filepath.Separator)) {
		return fmt.Errorf("seed tpm: tpm-state-dir %q is not below %q", c.stateDir, root)
	}
	if c.mode == SeedTpmModeVerify && !isSha256Hex(c.fingerprint) {
		return fmt.Errorf("seed tpm: verify mode needs tpm-fingerprint as 64 lowercase hex chars, got %q", c.fingerprint)
	}
	if c.lockTimeout <= 0 {
		return errors.New("seed tpm: swtpm_lock_timeout must be positive")
	}
	return nil
}

func isSha256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// checkSentinel verifies the shared TPM filesystem is the one we expect.
func checkSentinel(path, expectedFsid string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("seed tpm: cannot read sentinel %s (is the shared TPM filesystem mounted?): %w", path, err)
	}
	got := strings.TrimSpace(string(data))
	if got != expectedFsid {
		return fmt.Errorf("seed tpm: sentinel %s contains %q, expected fsid %q", path, got, expectedFsid)
	}
	return nil
}

// checkSameFilesystem makes sure dir is on the same filesystem (st_dev) as
// the sentinel, so a dir that shadows the mount point cannot slip through.
func checkSameFilesystem(sentinel, dir string) error {
	var a, b unix.Stat_t
	if err := unix.Stat(sentinel, &a); err != nil {
		return fmt.Errorf("seed tpm: stat %s: %w", sentinel, err)
	}
	if err := unix.Stat(dir, &b); err != nil {
		return fmt.Errorf("seed tpm: stat %s: %w", dir, err)
	}
	if a.Dev != b.Dev {
		return fmt.Errorf("seed tpm: %s is not on the same filesystem as sentinel %s", dir, sentinel)
	}
	return nil
}

// acquireSessionLock takes an exclusive flock on <stateDir>/.session-lock,
// polling until timeout or ctx cancellation.
func acquireSessionLock(ctx context.Context, stateDir string, timeout time.Duration) (*os.File, error) {
	path := filepath.Join(stateDir, swtpmSessionLockName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("seed tpm: open %s: %w", path, err)
	}
	deadline := time.Now().Add(timeout)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EINTR {
			f.Close()
			return nil, fmt.Errorf("seed tpm: flock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("seed tpm: timed out after %s waiting for session lock %s (another swtpm holds this TPM)", timeout, path)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("seed tpm: waiting for session lock %s: %w", path, ctx.Err())
		case <-time.After(swtpmLockPollInterval):
		}
	}
}

// writeFileAtomic writes data to path via a temp file + fsync + rename.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// tailBuffer forwards swtpm output to the log and keeps the tail for errors.
type tailBuffer struct {
	mu     sync.Mutex
	buf    []byte
	logger *log.Entry
}

const tailBufferMax = 4096

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line != "" {
			t.logger.WithField("swtpm", line).Warn("swtpm output")
		}
	}
	t.buf = append(t.buf, p...)
	if len(t.buf) > tailBufferMax {
		t.buf = t.buf[len(t.buf)-tailBufferMax:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.TrimSpace(string(t.buf))
}

// swtpm is the shim-owned swtpm process for one sandbox.
type swtpm struct {
	cfg swtpmConfig

	lockFile *os.File
	cmd      *exec.Cmd
	pid      int
	done     chan struct{} // closed when the swtpm process has exited
	waitErr  error
	output   *tailBuffer

	stopping atomic.Bool
	onQuit   atomic.Value // onQuitFunc, set by arm()
	stopOnce sync.Once

	// Fingerprint computed at start.
	Fingerprint string
}

func newSwtpm(cfg swtpmConfig) *swtpm {
	return &swtpm{cfg: cfg}
}

func (s *swtpm) Logger() *log.Entry {
	return hvLogger.WithFields(log.Fields{
		"subsystem": "swtpm",
		"state-dir": s.cfg.stateDir,
		"tpm-mode":  s.cfg.mode,
	})
}

// Start runs steps 1-5. On error nothing is left running and the lock is
// released.
func (s *swtpm) Start(ctx context.Context) (err error) {
	cfg := &s.cfg
	if err := cfg.validate(); err != nil {
		return err
	}

	defer func() {
		if err != nil {
			s.Stop(ctx)
		}
	}()

	// 1. sentinel
	if err := checkSentinel(cfg.sentinelPath, cfg.expectedFsid); err != nil {
		return err
	}

	if cfg.mode == SeedTpmModeCreate {
		if err := os.Mkdir(cfg.stateDir, 0755); err != nil && !os.IsExist(err) {
			return fmt.Errorf("seed tpm: create state dir: %w", err)
		}
	}
	if st, err := os.Lstat(cfg.stateDir); err != nil {
		return fmt.Errorf("seed tpm: state dir: %w", err)
	} else if !st.IsDir() {
		return fmt.Errorf("seed tpm: state dir %s is not a directory", cfg.stateDir)
	}
	if err := checkSameFilesystem(cfg.sentinelPath, cfg.stateDir); err != nil {
		return err
	}

	// 2. lock
	s.Logger().WithField("timeout", cfg.lockTimeout).Info("waiting for TPM session lock")
	if s.lockFile, err = acquireSessionLock(ctx, cfg.stateDir, cfg.lockTimeout); err != nil {
		return err
	}
	s.Logger().Info("acquired TPM session lock")

	permall := filepath.Join(cfg.stateDir, swtpmPermallName)
	_, statErr := os.Stat(permall)
	switch {
	case cfg.mode == SeedTpmModeCreate && statErr == nil:
		return fmt.Errorf("seed tpm: create mode but %s already exists; refusing to replace an existing TPM", permall)
	case cfg.mode == SeedTpmModeCreate && !os.IsNotExist(statErr):
		return fmt.Errorf("seed tpm: stat %s: %w", permall, statErr)
	case cfg.mode == SeedTpmModeVerify && statErr != nil:
		return fmt.Errorf("seed tpm: verify mode but cannot use %s: %w", permall, statErr)
	}

	// 3. swtpm
	if err := s.launch(); err != nil {
		return err
	}

	// 4. fingerprint
	fp, err := swtpmFingerprint(ctx, cfg.socketPath, s.done)
	if err != nil {
		return fmt.Errorf("seed tpm: computing TPM fingerprint: %w%s", err, s.outputSuffix())
	}
	s.Fingerprint = fp

	// 5. record / verify
	switch cfg.mode {
	case SeedTpmModeCreate:
		if err := writeFileAtomic(filepath.Join(cfg.stateDir, swtpmFingerprintName), []byte(fp), 0644); err != nil {
			return fmt.Errorf("seed tpm: writing fingerprint: %w", err)
		}
		s.Logger().WithField("fingerprint", fp).Info("created new TPM")
	case SeedTpmModeVerify:
		if fp != cfg.fingerprint {
			return fmt.Errorf("seed tpm: TPM fingerprint mismatch for %s: expected %s (annotation), got %s (state on disk)", cfg.stateDir, cfg.fingerprint, fp)
		}
		s.Logger().WithField("fingerprint", fp).Info("verified TPM fingerprint")
	}

	return nil
}

func (s *swtpm) args() []string {
	return []string{
		"socket", "--tpm2",
		"--tpmstate", "backend-uri=seed://" + s.cfg.stateDir,
		"--ctrl", "type=unixio,path=" + s.cfg.socketPath,
		"--flags", "startup-clear",
	}
}

func (s *swtpm) env() []string {
	env := []string{"SWTPM_SEED_VOLATILE_DIR=" + s.cfg.volatileDir}
	if s.cfg.mode == SeedTpmModeCreate {
		env = append(env, "SWTPM_SEED_ALLOW_CREATE=1")
	}
	return env
}

func (s *swtpm) launch() error {
	cfg := &s.cfg

	os.RemoveAll(cfg.volatileDir)
	if err := os.MkdirAll(cfg.volatileDir, 0700); err != nil {
		return fmt.Errorf("seed tpm: create volatile dir: %w", err)
	}
	os.Remove(cfg.socketPath)

	s.output = &tailBuffer{logger: s.Logger()}
	cmd := exec.Command(cfg.path, s.args()...)
	cmd.Env = s.env()
	cmd.Stdout = s.output
	cmd.Stderr = s.output
	// Share the session lock's open file description with swtpm (fd 3):
	// flock is held until every holder closes it, so even if swtpm somehow
	// outlived the shim the lock would stay held while it runs.
	cmd.ExtraFiles = []*os.File{s.lockFile}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGTERM,
	}
	s.cmd = cmd
	s.done = make(chan struct{})

	s.Logger().WithFields(log.Fields{"path": cfg.path, "args": strings.Join(s.args(), " ")}).Info("starting swtpm")

	started := make(chan error, 1)
	go func() {
		// Pdeathsig fires when the *thread* that forked the child exits,
		// not the process. Pin this goroutine to its thread and never
		// unlock it, so that thread lives until swtpm has exited.
		runtime.LockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		s.waitErr = cmd.Wait()
		close(s.done)
		if s.stopping.Load() {
			return
		}
		s.Logger().WithError(s.waitErr).WithField("output", s.output.String()).Error("swtpm exited unexpectedly")
		if q, ok := s.onQuit.Load().(onQuitFunc); ok && q != nil {
			go q()
		}
	}()
	if err := <-started; err != nil {
		s.done = nil
		return fmt.Errorf("seed tpm: starting swtpm: %w", err)
	}
	s.pid = cmd.Process.Pid
	s.Logger().WithField("pid", s.pid).Info("swtpm started")
	return nil
}

func (s *swtpm) outputSuffix() string {
	if s.output == nil {
		return ""
	}
	if out := s.output.String(); out != "" {
		return " (swtpm: " + strings.ReplaceAll(out, "\n", "; ") + ")"
	}
	return ""
}

// arm installs onQuit, called if swtpm dies on its own from now on. Called
// once cloud-hypervisor is up: before that, a dying swtpm surfaces as a
// Start error instead.
func (s *swtpm) arm(onQuit onQuitFunc) {
	s.onQuit.Store(onQuit)
	if s.done != nil {
		select {
		case <-s.done:
			if !s.stopping.Load() {
				go onQuit()
			}
		default:
		}
	}
}

// Stop terminates swtpm, then releases the session lock and removes the
// local files. Safe to call more than once.
func (s *swtpm) Stop(ctx context.Context) error {
	var err error
	s.stopOnce.Do(func() { err = s.stop() })
	return err
}

func (s *swtpm) stop() error {
	s.stopping.Store(true)
	var err error

	if s.done != nil {
		select {
		case <-s.done:
		default:
			s.Logger().WithField("pid", s.pid).Info("stopping swtpm")
			// Negative pid: the whole process group (Setpgid above).
			syscall.Kill(-s.pid, syscall.SIGTERM)
			select {
			case <-s.done:
			case <-time.After(swtpmStopTimeout):
				s.Logger().WithField("pid", s.pid).Warn("swtpm did not exit after SIGTERM, sending SIGKILL")
				syscall.Kill(-s.pid, syscall.SIGKILL)
				select {
				case <-s.done:
				case <-time.After(swtpmStopTimeout):
					err = fmt.Errorf("seed tpm: swtpm (pid %d) did not exit after SIGKILL", s.pid)
				}
			}
		}
	}

	if s.lockFile != nil {
		// Deliberately no LOCK_UN: that would drop the lock for swtpm too
		// if it were still alive. Closing our descriptor releases the lock
		// once swtpm (the other holder) has exited.
		s.lockFile.Close()
		s.lockFile = nil
	}
	if err == nil {
		os.RemoveAll(s.cfg.volatileDir)
		os.Remove(s.cfg.socketPath)
	}
	if err != nil {
		s.Logger().WithError(err).Error("failed to stop swtpm")
	} else {
		s.Logger().Info("swtpm stopped, TPM session lock released")
	}
	return err
}

// -------------------------------------------------------------------------
// swtpm control channel
// -------------------------------------------------------------------------

// swtpm control channel commands (swtpm's tpm_ioctl.h, socket encoding:
// 4-byte big-endian command code, then the request body; responses start
// with a 4-byte big-endian TPM result code).
const (
	swtpmCmdGetCapability = 1
	swtpmCmdSetDatafd     = 16
)

type swtpmCtrl struct {
	conn *net.UnixConn
}

// dialSwtpmCtrl waits for swtpm's control socket and connects to it.
func dialSwtpmCtrl(ctx context.Context, path string, exited <-chan struct{}) (*swtpmCtrl, error) {
	deadline := time.Now().Add(swtpmSocketWaitTimeout)
	for {
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err == nil {
			return &swtpmCtrl{conn: conn}, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("swtpm control socket %s not ready after %s: %w", path, swtpmSocketWaitTimeout, err)
		}
		select {
		case <-exited:
			return nil, errors.New("swtpm exited during startup")
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (c *swtpmCtrl) Close() error { return c.conn.Close() }

// command sends cmd with optional body and fd, and returns the response.
func (c *swtpmCtrl) command(cmd uint32, body []byte, fd int, respLen int) ([]byte, error) {
	req := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(req, cmd)
	req = append(req, body...)
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	c.conn.SetDeadline(time.Now().Add(swtpmIOTimeout))
	defer c.conn.SetDeadline(time.Time{})
	if _, _, err := c.conn.WriteMsgUnix(req, oob, nil); err != nil {
		return nil, fmt.Errorf("swtpm ctrl cmd %d: write: %w", cmd, err)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(c.conn, resp); err != nil {
		return nil, fmt.Errorf("swtpm ctrl cmd %d: read: %w", cmd, err)
	}
	if res := binary.BigEndian.Uint32(resp); res != 0 {
		return nil, fmt.Errorf("swtpm ctrl cmd %d: result 0x%x", cmd, res)
	}
	return resp, nil
}

// setDataFd creates a socketpair, hands one end to swtpm with CMD_SET_DATAFD
// (exactly what cloud-hypervisor does) and returns the other end.
func (c *swtpmCtrl) setDataFd() (*net.UnixConn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}
	_, err = c.command(swtpmCmdSetDatafd, nil, fds[1], 4)
	unix.Close(fds[1])
	if err != nil {
		unix.Close(fds[0])
		return nil, err
	}
	f := os.NewFile(uintptr(fds[0]), "swtpm-data")
	defer f.Close() // FileConn dups the fd
	conn, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	return conn.(*net.UnixConn), nil
}

// -------------------------------------------------------------------------
// TPM 2.0 commands (just enough for CreatePrimary + FlushContext)
// -------------------------------------------------------------------------

const (
	tpmStNoSessions = 0x8001
	tpmStSessions   = 0x8002

	tpmCcCreatePrimary = 0x00000131
	tpmCcFlushContext  = 0x00000165
	tpmCcStartup       = 0x00000144

	tpmRhOwner = 0x40000001
	tpmRsPw    = 0x40000009

	tpmSuClear = 0x0000

	tpmAlgAES    = 0x0006
	tpmAlgSHA256 = 0x000B
	tpmAlgNull   = 0x0010
	tpmAlgECC    = 0x0023
	tpmAlgCFB    = 0x0043

	tpmEccNistP256 = 0x0003

	tpmaObjectFixedTPM            = 1 << 1
	tpmaObjectFixedParent         = 1 << 4
	tpmaObjectSensitiveDataOrigin = 1 << 5
	tpmaObjectUserWithAuth        = 1 << 6
	tpmaObjectNoDA                = 1 << 10
	tpmaObjectRestricted          = 1 << 16
	tpmaObjectDecrypt             = 1 << 17

	tpmRcSuccess    = 0x000
	tpmRcInitialize = 0x100
	tpmRcRetry      = 0x922
	tpmRcYielded    = 0x908
	tpmRcTesting    = 0x90A
)

// srkTemplate returns the marshaled TPMT_PUBLIC used as the CreatePrimary
// template (TCG-style ECC P-256 storage root key):
//
//	0023                type       TPM_ALG_ECC
//	000b                nameAlg    TPM_ALG_SHA256
//	00030472            objectAttributes fixedTPM|fixedParent|
//	                               sensitiveDataOrigin|userWithAuth|noDA|
//	                               restricted|decrypt
//	0000                authPolicy (empty TPM2B_DIGEST)
//	0006 0080 0043      symmetric  AES, 128 bits, CFB
//	0010                scheme     TPM_ALG_NULL
//	0003                curveID    TPM_ECC_NIST_P256
//	0010                kdf        TPM_ALG_NULL
//	0020 00*32          unique.x   32 zero bytes
//	0020 00*32          unique.y   32 zero bytes
func srkTemplate() []byte {
	var b bytes.Buffer
	be16 := func(v uint16) { binary.Write(&b, binary.BigEndian, v) }
	be32 := func(v uint32) { binary.Write(&b, binary.BigEndian, v) }

	be16(tpmAlgECC)
	be16(tpmAlgSHA256)
	be32(tpmaObjectFixedTPM | tpmaObjectFixedParent | tpmaObjectSensitiveDataOrigin |
		tpmaObjectUserWithAuth | tpmaObjectNoDA | tpmaObjectRestricted | tpmaObjectDecrypt)
	be16(0) // authPolicy
	be16(tpmAlgAES)
	be16(128)
	be16(tpmAlgCFB)
	be16(tpmAlgNull)     // scheme
	be16(tpmEccNistP256) // curveID
	be16(tpmAlgNull)     // kdf
	be16(32)
	b.Write(make([]byte, 32)) // unique.x
	be16(32)
	b.Write(make([]byte, 32)) // unique.y
	return b.Bytes()
}

// srkTemplatePrefixLen is the length of the part of TPMT_PUBLIC that the
// TPM must echo back unchanged (everything before unique).
const srkTemplatePrefixLen = 2 + 2 + 4 + 2 + 6 + 2 + 2 + 2

func tpmCommand(tag uint16, cc uint32, body []byte) []byte {
	cmd := make([]byte, 10, 10+len(body))
	binary.BigEndian.PutUint16(cmd[0:], tag)
	binary.BigEndian.PutUint32(cmd[2:], uint32(10+len(body)))
	binary.BigEndian.PutUint32(cmd[6:], cc)
	return append(cmd, body...)
}

// buildCreatePrimarySRK marshals TPM2_CreatePrimary(TPM_RH_OWNER, srkTemplate)
// with an empty-password session for the owner hierarchy.
func buildCreatePrimarySRK() []byte {
	var b bytes.Buffer
	be16 := func(v uint16) { binary.Write(&b, binary.BigEndian, v) }
	be32 := func(v uint32) { binary.Write(&b, binary.BigEndian, v) }

	be32(tpmRhOwner) // primaryHandle
	// authorization area: one TPMS_AUTH_COMMAND for TPM_RS_PW, empty auth
	be32(9)
	be32(tpmRsPw)  // sessionHandle
	be16(0)        // nonce
	b.WriteByte(0) // sessionAttributes
	be16(0)        // hmac (password)
	// inSensitive: TPM2B_SENSITIVE_CREATE { userAuth = empty, data = empty }
	be16(4)
	be16(0)
	be16(0)
	// inPublic: TPM2B_PUBLIC
	tmpl := srkTemplate()
	be16(uint16(len(tmpl)))
	b.Write(tmpl)
	be16(0) // outsideInfo
	be32(0) // creationPCR: TPML_PCR_SELECTION count 0
	return tpmCommand(tpmStSessions, tpmCcCreatePrimary, b.Bytes())
}

func buildFlushContext(handle uint32) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, handle)
	return tpmCommand(tpmStNoSessions, tpmCcFlushContext, body)
}

func buildStartupClear() []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, tpmSuClear)
	return tpmCommand(tpmStNoSessions, tpmCcStartup, body)
}

type tpmError uint32

func (e tpmError) Error() string { return fmt.Sprintf("TPM error 0x%03x", uint32(e)) }

// tpmResponseCode validates the response header and returns the TPM_RC.
func tpmResponseCode(resp []byte) (uint32, error) {
	if len(resp) < 10 {
		return 0, fmt.Errorf("short TPM response (%d bytes)", len(resp))
	}
	if size := binary.BigEndian.Uint32(resp[2:]); int(size) != len(resp) {
		return 0, fmt.Errorf("TPM response size %d does not match %d bytes read", size, len(resp))
	}
	return binary.BigEndian.Uint32(resp[6:]), nil
}

type tpmReader struct {
	b   []byte
	err error
}

func (r *tpmReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n > len(r.b) {
		r.err = errors.New("truncated TPM response")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *tpmReader) u16() uint16 {
	if v := r.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

func (r *tpmReader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

func (r *tpmReader) tpm2b() []byte { return r.take(int(r.u16())) }

// parseCreatePrimaryResponse returns the object handle and the marshaled
// TPMT_PUBLIC of outPublic (without its TPM2B size prefix). It also checks
// that the TPM echoed the template and that the returned name is
// nameAlg || SHA256(publicArea).
func parseCreatePrimaryResponse(resp []byte) (uint32, []byte, error) {
	rc, err := tpmResponseCode(resp)
	if err != nil {
		return 0, nil, err
	}
	if rc != tpmRcSuccess {
		return 0, nil, tpmError(rc)
	}
	r := &tpmReader{b: resp[10:]}
	handle := r.u32()
	paramSize := r.u32()
	params := r.take(int(paramSize))
	if r.err != nil {
		return 0, nil, r.err
	}
	p := &tpmReader{b: params}
	pub := p.tpm2b()
	p.tpm2b() // creationData
	p.tpm2b() // creationHash
	p.u16()   // creationTicket.tag
	p.u32()   // creationTicket.hierarchy
	p.tpm2b() // creationTicket.digest
	name := p.tpm2b()
	if p.err != nil {
		return 0, nil, p.err
	}

	tmpl := srkTemplate()
	if len(pub) < srkTemplatePrefixLen || !bytes.Equal(pub[:srkTemplatePrefixLen], tmpl[:srkTemplatePrefixLen]) {
		return 0, nil, fmt.Errorf("TPM returned a public area that does not match the SRK template: %x", pub)
	}
	digest := sha256.Sum256(pub)
	wantName := append([]byte{0x00, 0x0b}, digest[:]...)
	if !bytes.Equal(name, wantName) {
		return 0, nil, fmt.Errorf("TPM returned name %x, expected %x", name, wantName)
	}
	out := make([]byte, len(pub))
	copy(out, pub)
	return handle, out, nil
}

// fingerprintFromPublic is the TPM fingerprint: lowercase hex SHA-256 of the
// marshaled TPMT_PUBLIC of the SRK, exactly as returned by CreatePrimary in
// outPublic, without the 2-byte TPM2B_PUBLIC size prefix.
func fingerprintFromPublic(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// tpmTransact sends one TPM command on the data channel and reads one
// complete response.
func tpmTransact(conn net.Conn, cmd []byte) ([]byte, error) {
	conn.SetDeadline(time.Now().Add(swtpmIOTimeout))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write(cmd); err != nil {
		return nil, fmt.Errorf("TPM write: %w", err)
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("TPM read: %w", err)
	}
	size := binary.BigEndian.Uint32(hdr[2:])
	if size < 10 || size > 1<<16 {
		return nil, fmt.Errorf("bad TPM response size %d", size)
	}
	resp := make([]byte, size)
	copy(resp, hdr)
	if _, err := io.ReadFull(conn, resp[10:]); err != nil {
		return nil, fmt.Errorf("TPM read: %w", err)
	}
	return resp, nil
}

// tpmTransactRetry retries on TPM_RC_RETRY/YIELDED/TESTING, and issues
// TPM2_Startup(CLEAR) once if the TPM reports it is not started.
func tpmTransactRetry(conn net.Conn, cmd []byte) ([]byte, error) {
	startupSent := false
	for attempt := 0; attempt < 20; attempt++ {
		resp, err := tpmTransact(conn, cmd)
		if err != nil {
			return nil, err
		}
		rc, err := tpmResponseCode(resp)
		if err != nil {
			return nil, err
		}
		switch rc {
		case tpmRcRetry, tpmRcYielded, tpmRcTesting:
			time.Sleep(50 * time.Millisecond)
			continue
		case tpmRcInitialize:
			if startupSent {
				return resp, nil
			}
			startupSent = true
			sresp, err := tpmTransact(conn, buildStartupClear())
			if err != nil {
				return nil, err
			}
			if src, err := tpmResponseCode(sresp); err != nil {
				return nil, err
			} else if src != tpmRcSuccess && src != tpmRcInitialize {
				return nil, fmt.Errorf("TPM2_Startup: %w", tpmError(src))
			}
			continue
		}
		return resp, nil
	}
	return nil, errors.New("TPM kept asking to retry")
}

// computeSrkFingerprint runs CreatePrimary + FlushContext on an open data
// channel and returns the fingerprint.
func computeSrkFingerprint(conn net.Conn) (string, error) {
	resp, err := tpmTransactRetry(conn, buildCreatePrimarySRK())
	if err != nil {
		return "", fmt.Errorf("TPM2_CreatePrimary: %w", err)
	}
	handle, pub, err := parseCreatePrimaryResponse(resp)
	if err != nil {
		return "", fmt.Errorf("TPM2_CreatePrimary: %w", err)
	}
	fresp, err := tpmTransactRetry(conn, buildFlushContext(handle))
	if err != nil {
		return "", fmt.Errorf("TPM2_FlushContext: %w", err)
	}
	if rc, err := tpmResponseCode(fresp); err != nil {
		return "", fmt.Errorf("TPM2_FlushContext: %w", err)
	} else if rc != tpmRcSuccess {
		return "", fmt.Errorf("TPM2_FlushContext: %w", tpmError(rc))
	}
	return fingerprintFromPublic(pub), nil
}

// swtpmFingerprint connects to swtpm's control socket, sets up a data
// channel, computes the SRK fingerprint and hands the TPM back in a state
// cloud-hypervisor can attach to: the data channel is closed and swtpm is
// known to have processed that (so its next CMD_SET_DATAFD succeeds).
func swtpmFingerprint(ctx context.Context, ctrlPath string, exited <-chan struct{}) (string, error) {
	ctrl, err := dialSwtpmCtrl(ctx, ctrlPath, exited)
	if err != nil {
		return "", err
	}
	defer ctrl.Close()

	data, err := ctrl.setDataFd()
	if err != nil {
		return "", err
	}
	fp, err := computeSrkFingerprint(data)
	data.Close()
	if err != nil {
		return "", err
	}

	// swtpm accepts only one data fd at a time and forgets it when it sees
	// the hangup. It polls the data and control fds together and handles a
	// data hangup before control input within the same poll round, so once
	// this control round trip completes the hangup has been processed.
	if _, err := ctrl.command(swtpmCmdGetCapability, nil, -1, 8); err != nil {
		return "", fmt.Errorf("swtpm handoff sync: %w", err)
	}
	return fp, nil
}
