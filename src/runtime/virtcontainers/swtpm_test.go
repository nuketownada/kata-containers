// Copyright (c) 2026 Seed contributors
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// Minimal stand-in for testify/require (not vendored in kata).
type requireT struct{}

var require requireT

func (requireT) NoError(t *testing.T, err error, msg ...interface{}) {
	t.Helper()
	if !assert.NoError(t, err, msg...) {
		t.FailNow()
	}
}

func (requireT) Error(t *testing.T, err error, msg ...interface{}) {
	t.Helper()
	if !assert.Error(t, err, msg...) {
		t.FailNow()
	}
}

func (requireT) True(t *testing.T, v bool, msg ...interface{}) {
	t.Helper()
	if !assert.True(t, v, msg...) {
		t.FailNow()
	}
}

// Golden bytes of the SRK template; the controller's offline backfill tool
// and tpm2-tools must produce a TPM key from exactly this template.
const srkTemplateHex = "0023" + "000b" + "00030472" + "0000" +
	"0006" + "0080" + "0043" + "0010" + "0003" + "0010" +
	"0020" + "0000000000000000000000000000000000000000000000000000000000000000" +
	"0020" + "0000000000000000000000000000000000000000000000000000000000000000"

func TestSrkTemplateBytes(t *testing.T) {
	assert.Equal(t, srkTemplateHex, hex.EncodeToString(srkTemplate()))
	assert.Equal(t, srkTemplateHex[:srkTemplatePrefixLen*2], hex.EncodeToString(srkTemplate()[:srkTemplatePrefixLen]))
}

func TestBuildCreatePrimarySRK(t *testing.T) {
	cmd := buildCreatePrimarySRK()
	want := "8002" + "%08x" + "00000131" + // header
		"40000001" + // TPM_RH_OWNER
		"00000009" + "40000009" + "0000" + "00" + "0000" + // password session
		"0004" + "0000" + "0000" + // inSensitive
		"%04x" + srkTemplateHex + // inPublic
		"0000" + // outsideInfo
		"00000000" // creationPCR
	tmplLen := len(srkTemplateHex) / 2
	want = strings.Replace(want, "%04x", hex.EncodeToString([]byte{byte(tmplLen >> 8), byte(tmplLen)}), 1)
	size := make([]byte, 4)
	binary.BigEndian.PutUint32(size, uint32(len(cmd)))
	want = strings.Replace(want, "%08x", hex.EncodeToString(size), 1)
	assert.Equal(t, want, hex.EncodeToString(cmd))
}

func TestBuildFlushContext(t *testing.T) {
	assert.Equal(t, "80010000000e0000016580000000", hex.EncodeToString(buildFlushContext(0x80000000)))
}

// fakeCreatePrimaryResponse builds a CreatePrimary response around pub.
func fakeCreatePrimaryResponse(handle uint32, pub, name []byte) []byte {
	var params []byte
	tpm2b := func(b []byte) {
		params = binary.BigEndian.AppendUint16(params, uint16(len(b)))
		params = append(params, b...)
	}
	tpm2b(pub)
	tpm2b([]byte{1, 2, 3})                             // creationData
	tpm2b(make([]byte, 32))                            // creationHash
	params = append(params, 0x80, 0x21, 0x40, 0, 0, 1) // ticket tag + hierarchy
	tpm2b(make([]byte, 32))                            // ticket digest
	tpm2b(name)

	body := binary.BigEndian.AppendUint32(nil, handle)
	body = binary.BigEndian.AppendUint32(body, uint32(len(params)))
	body = append(body, params...)
	body = append(body, 0, 0, 1, 0, 0) // response auth area
	resp := []byte{0x80, 0x02, 0, 0, 0, 0, 0, 0, 0, 0}
	resp = append(resp, body...)
	binary.BigEndian.PutUint32(resp[2:], uint32(len(resp)))
	return resp
}

func fakeSrkPublic() []byte {
	pub := srkTemplate()[:srkTemplatePrefixLen]
	pub = append([]byte{}, pub...)
	pub = append(pub, 0, 32)
	pub = append(pub, []byte(strings.Repeat("x", 32))...)
	pub = append(pub, 0, 32)
	pub = append(pub, []byte(strings.Repeat("y", 32))...)
	return pub
}

func TestParseCreatePrimaryResponse(t *testing.T) {
	pub := fakeSrkPublic()
	d := sha256.Sum256(pub)
	name := append([]byte{0, 0x0b}, d[:]...)

	h, got, err := parseCreatePrimaryResponse(fakeCreatePrimaryResponse(0x80000000, pub, name))
	require.NoError(t, err)
	assert.Equal(t, uint32(0x80000000), h)
	assert.Equal(t, pub, got)
	assert.Equal(t, hex.EncodeToString(d[:]), fingerprintFromPublic(got))

	// name that does not match the public area
	bad := append([]byte{}, name...)
	bad[5] ^= 1
	_, _, err = parseCreatePrimaryResponse(fakeCreatePrimaryResponse(0x80000000, pub, bad))
	assert.ErrorContains(t, err, "name")

	// public area that does not match the template
	pub2 := append([]byte{}, pub...)
	pub2[5] ^= 1 // objectAttributes
	d2 := sha256.Sum256(pub2)
	_, _, err = parseCreatePrimaryResponse(fakeCreatePrimaryResponse(0x80000000, pub2, append([]byte{0, 0x0b}, d2[:]...)))
	assert.ErrorContains(t, err, "template")

	// TPM error
	_, _, err = parseCreatePrimaryResponse([]byte{0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x09, 0x8e})
	assert.ErrorContains(t, err, "0x98e")

	// truncated
	r := fakeCreatePrimaryResponse(0x80000000, pub, name)
	r = r[:40]
	binary.BigEndian.PutUint32(r[2:], 40)
	_, _, err = parseCreatePrimaryResponse(r)
	assert.Error(t, err)
}

func TestIsSha256Hex(t *testing.T) {
	assert.True(t, isSha256Hex(strings.Repeat("a0", 32)))
	assert.False(t, isSha256Hex(strings.Repeat("A0", 32)))
	assert.False(t, isSha256Hex(strings.Repeat("a0", 31)))
	assert.False(t, isSha256Hex(strings.Repeat("g0", 32)))
}

func TestCheckSentinel(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".seed-fs")

	err := checkSentinel(p, "fsid")
	assert.ErrorContains(t, err, "cannot read sentinel")

	require.NoError(t, os.WriteFile(p, []byte("  58ec6b96-5df6-49f2-86c3-182501b0602d\n"), 0644))
	assert.NoError(t, checkSentinel(p, "58ec6b96-5df6-49f2-86c3-182501b0602d"))
	err = checkSentinel(p, "00000000-0000-0000-0000-000000000000")
	assert.ErrorContains(t, err, "expected fsid")
}

func testSwtpmConfig(root string) swtpmConfig {
	return swtpmConfig{
		path:         "/bin/swtpm",
		sentinelPath: filepath.Join(root, ".seed-fs"),
		expectedFsid: "fsid",
		lockTimeout:  time.Second,
		mode:         SeedTpmModeCreate,
		stateDir:     filepath.Join(root, "s-ns-inst"),
		socketPath:   "/run/vc/vm/x/swtpm.sock",
		volatileDir:  "/run/vc/vm/x/swtpm-volatile",
	}
}

func TestSwtpmConfigValidate(t *testing.T) {
	root := "/var/lib/seed-controller/tpm"
	ok := testSwtpmConfig(root)
	assert.NoError(t, ok.validate())

	fp := strings.Repeat("ab", 32)
	cases := map[string]func(c *swtpmConfig){
		"bad mode":           func(c *swtpmConfig) { c.mode = "maybe" },
		"no swtpm path":      func(c *swtpmConfig) { c.path = "" },
		"no fsid":            func(c *swtpmConfig) { c.expectedFsid = "" },
		"relative state dir": func(c *swtpmConfig) { c.stateDir = "tpm/x" },
		"unclean state dir":  func(c *swtpmConfig) { c.stateDir = root + "/a/../../../etc" },
		"outside root":       func(c *swtpmConfig) { c.stateDir = "/etc/x" },
		"root itself":        func(c *swtpmConfig) { c.stateDir = root },
		"prefix trick":       func(c *swtpmConfig) { c.stateDir = root + "x/y" },
		"verify no fp":       func(c *swtpmConfig) { c.mode = SeedTpmModeVerify },
		"verify upper fp":    func(c *swtpmConfig) { c.mode = SeedTpmModeVerify; c.fingerprint = strings.ToUpper(fp) },
		"zero timeout":       func(c *swtpmConfig) { c.lockTimeout = 0 },
	}
	for name, mutate := range cases {
		c := testSwtpmConfig(root)
		mutate(&c)
		assert.Error(t, c.validate(), name)
	}

	v := testSwtpmConfig(root)
	v.mode = SeedTpmModeVerify
	v.fingerprint = fp
	assert.NoError(t, v.validate())
}

func TestNewSwtpmConfigDefaults(t *testing.T) {
	hc := &HypervisorConfig{SwtpmPath: "/x/swtpm", SeedTpmMode: "create", SeedTpmStateDir: "/var/lib/seed-controller/tpm/a"}
	c := newSwtpmConfig(hc, "/run/vc/vm/abc")
	assert.Equal(t, DefaultSwtpmSentinelPath, c.sentinelPath)
	assert.Equal(t, DefaultSwtpmLockTimeout*time.Second, c.lockTimeout)
	assert.Equal(t, "/run/vc/vm/abc/swtpm.sock", c.socketPath)
	assert.Equal(t, "/run/vc/vm/abc/swtpm-volatile", c.volatileDir)
}

func TestAcquireSessionLock(t *testing.T) {
	old := swtpmLockPollInterval
	swtpmLockPollInterval = 10 * time.Millisecond
	defer func() { swtpmLockPollInterval = old }()

	dir := t.TempDir()
	ctx := context.Background()

	f1, err := acquireSessionLock(ctx, dir, time.Second)
	require.NoError(t, err)

	// flock conflicts between separate open file descriptions, even in
	// one process.
	start := time.Now()
	_, err = acquireSessionLock(ctx, dir, 200*time.Millisecond)
	assert.ErrorContains(t, err, "timed out")
	assert.GreaterOrEqual(t, time.Since(start), 200*time.Millisecond)

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = acquireSessionLock(cctx, dir, time.Minute)
	assert.ErrorIs(t, err, context.Canceled)

	// released when the holder closes
	go func() {
		time.Sleep(100 * time.Millisecond)
		f1.Close()
	}()
	f2, err := acquireSessionLock(ctx, dir, 5*time.Second)
	require.NoError(t, err)
	f2.Close()
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tpm-fingerprint")
	require.NoError(t, writeFileAtomic(p, []byte("one"), 0644))
	require.NoError(t, writeFileAtomic(p, []byte("two"), 0644))
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "two", string(b))
	ents, _ := os.ReadDir(dir)
	assert.Len(t, ents, 1, "no temp files left behind")
}

func TestSwtpmStopNotStarted(t *testing.T) {
	s := newSwtpm(testSwtpmConfig(t.TempDir()))
	assert.NoError(t, s.Stop(context.Background()))
	assert.NoError(t, s.Stop(context.Background()))
}

// ---------------------------------------------------------------------------
// Integration tests against a real swtpm built with the seed:// backend.
// SEED_TEST_SWTPM=/path/to/swtpm go test ./virtcontainers/ -run Swtpm
// ---------------------------------------------------------------------------

type swtpmEnv struct {
	root    string // stands in for /var/lib/seed-controller/tpm
	runDir  string // stands in for /run/vc/vm/<id>; short, for socket paths
	swtpm   string
	fsid    string
	timeout time.Duration
}

func newSwtpmEnv(t *testing.T) *swtpmEnv {
	bin := os.Getenv("SEED_TEST_SWTPM")
	if bin == "" {
		t.Skip("SEED_TEST_SWTPM not set")
	}
	root := t.TempDir()
	run, err := os.MkdirTemp("", "sw")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(run) })
	e := &swtpmEnv{root: root, runDir: run, swtpm: bin, fsid: "58ec6b96-5df6-49f2-86c3-182501b0602d", timeout: time.Second}
	require.NoError(t, os.WriteFile(filepath.Join(root, ".seed-fs"), []byte(e.fsid+"\n"), 0644))
	return e
}

func (e *swtpmEnv) cfg(mode, inst, fp string) swtpmConfig {
	return swtpmConfig{
		path:         e.swtpm,
		sentinelPath: filepath.Join(e.root, ".seed-fs"),
		expectedFsid: e.fsid,
		lockTimeout:  e.timeout,
		mode:         mode,
		stateDir:     filepath.Join(e.root, inst),
		fingerprint:  fp,
		socketPath:   filepath.Join(e.runDir, "swtpm.sock"),
		volatileDir:  filepath.Join(e.runDir, "swtpm-volatile"),
	}
}

func pidAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func TestSwtpmIntegrationLifecycle(t *testing.T) {
	e := newSwtpmEnv(t)
	ctx := context.Background()

	// create: manufactures a TPM, records the fingerprint
	s := newSwtpm(e.cfg(SeedTpmModeCreate, "s-ns-web", ""))
	require.NoError(t, s.Start(ctx))
	fp := s.Fingerprint
	require.True(t, isSha256Hex(fp), fp)
	pid := s.pid
	assert.True(t, pidAlive(pid))
	b, err := os.ReadFile(filepath.Join(e.root, "s-ns-web", "tpm-fingerprint"))
	require.NoError(t, err)
	assert.Equal(t, fp, string(b))
	assert.FileExists(t, filepath.Join(e.root, "s-ns-web", "tpm2-00.permall"))

	// while running, nobody else gets the session lock
	_, err = acquireSessionLock(ctx, filepath.Join(e.root, "s-ns-web"), 300*time.Millisecond)
	assert.ErrorContains(t, err, "timed out")

	require.NoError(t, s.Stop(ctx))
	assert.False(t, pidAlive(pid), "swtpm still running after Stop")
	assert.NoDirExists(t, filepath.Join(e.runDir, "swtpm-volatile"))
	assert.NoFileExists(t, filepath.Join(e.runDir, "swtpm.sock"))
	l, err := acquireSessionLock(ctx, filepath.Join(e.root, "s-ns-web"), 300*time.Millisecond)
	require.NoError(t, err, "lock not released after Stop")
	l.Close()

	// verify with the right fingerprint: same TPM across restarts
	v := newSwtpm(e.cfg(SeedTpmModeVerify, "s-ns-web", fp))
	require.NoError(t, v.Start(ctx))
	assert.Equal(t, fp, v.Fingerprint)
	require.NoError(t, v.Stop(ctx))

	// verify with a wrong fingerprint: fails, swtpm gone, lock released
	wrong := strings.Repeat("0", 64)
	w := newSwtpm(e.cfg(SeedTpmModeVerify, "s-ns-web", wrong))
	err = w.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), wrong)
	assert.Contains(t, err.Error(), fp)
	assert.False(t, pidAlive(w.pid))
	l, err = acquireSessionLock(ctx, filepath.Join(e.root, "s-ns-web"), 300*time.Millisecond)
	require.NoError(t, err, "lock not released after failed verify")
	l.Close()

	// create over an existing TPM is refused
	c2 := newSwtpm(e.cfg(SeedTpmModeCreate, "s-ns-web", ""))
	assert.ErrorContains(t, c2.Start(ctx), "already exists")

	// a second created TPM is a different TPM
	o := newSwtpm(e.cfg(SeedTpmModeCreate, "s-ns-other", ""))
	require.NoError(t, o.Start(ctx))
	assert.NotEqual(t, fp, o.Fingerprint)
	require.NoError(t, o.Stop(ctx))
}

func TestSwtpmIntegrationRefusals(t *testing.T) {
	e := newSwtpmEnv(t)
	ctx := context.Background()

	// wrong sentinel content
	c := e.cfg(SeedTpmModeCreate, "s-ns-a", "")
	c.expectedFsid = "11111111-1111-1111-1111-111111111111"
	err := newSwtpm(c).Start(ctx)
	assert.ErrorContains(t, err, "expected fsid")
	assert.NoDirExists(t, c.stateDir, "state dir must not be created before the sentinel check")

	// missing sentinel
	c = e.cfg(SeedTpmModeCreate, "s-ns-a", "")
	c.sentinelPath = filepath.Join(e.root, ".missing")
	assert.ErrorContains(t, newSwtpm(c).Start(ctx), "cannot read sentinel")

	// verify without a permall (never manufacture in verify mode)
	require.NoError(t, os.Mkdir(filepath.Join(e.root, "s-ns-b"), 0755))
	c = e.cfg(SeedTpmModeVerify, "s-ns-b", strings.Repeat("a", 64))
	assert.ErrorContains(t, newSwtpm(c).Start(ctx), "verify mode but")
	assert.NoFileExists(t, filepath.Join(e.root, "s-ns-b", "tpm2-00.permall"))

	// verify against a missing state dir
	c = e.cfg(SeedTpmModeVerify, "s-ns-missing", strings.Repeat("a", 64))
	assert.ErrorContains(t, newSwtpm(c).Start(ctx), "state dir")
	assert.NoDirExists(t, c.stateDir)

	// lock held elsewhere -> timeout, swtpm never started
	require.NoError(t, os.Mkdir(filepath.Join(e.root, "s-ns-c"), 0755))
	held, err := acquireSessionLock(ctx, filepath.Join(e.root, "s-ns-c"), time.Second)
	require.NoError(t, err)
	c = e.cfg(SeedTpmModeCreate, "s-ns-c", "")
	c.lockTimeout = 500 * time.Millisecond
	s := newSwtpm(c)
	assert.ErrorContains(t, s.Start(ctx), "timed out")
	assert.Nil(t, s.cmd)
	held.Close()

	// swtpm that cannot start (bad binary) surfaces as an error
	c = e.cfg(SeedTpmModeCreate, "s-ns-d", "")
	c.path = "/nonexistent/swtpm"
	assert.ErrorContains(t, newSwtpm(c).Start(ctx), "starting swtpm")
	l, err := acquireSessionLock(ctx, c.stateDir, 300*time.Millisecond)
	require.NoError(t, err)
	l.Close()

	// state dir on a different filesystem than the sentinel
	if st, err := os.Stat("/dev/shm"); err == nil && st.IsDir() {
		other, err := os.MkdirTemp("/dev/shm", "seedtpm")
		require.NoError(t, err)
		defer os.RemoveAll(other)
		require.NoError(t, os.WriteFile(filepath.Join(other, ".seed-fs"), []byte(e.fsid), 0644))
		c = e.cfg(SeedTpmModeCreate, "x", "")
		c.sentinelPath = filepath.Join(other, ".seed-fs")
		// state dir is below the sentinel dir but is a mount of another fs:
		// simulate with a symlink to the test root, which Lstat rejects.
		require.NoError(t, os.Symlink(e.root, filepath.Join(other, "x")))
		c.stateDir = filepath.Join(other, "x")
		assert.Error(t, newSwtpm(c).Start(ctx))
	}
}

// TestSwtpmIntegrationHandoff replays cloud-hypervisor's exact control
// channel sequence (cloud-hypervisor tpm/src/emulator.rs + devices/src/tpm.rs,
// v49/v50) after the shim has used the TPM, then acts like the guest kernel.
func TestSwtpmIntegrationHandoff(t *testing.T) {
	e := newSwtpmEnv(t)
	ctx := context.Background()

	s := newSwtpm(e.cfg(SeedTpmModeCreate, "s-ns-h", ""))
	require.NoError(t, s.Start(ctx))
	defer s.Stop(ctx)

	quit := make(chan struct{})
	s.arm(func() { close(quit) })

	clhAttachAndCheck := func() {
		ctrl, err := dialSwtpmCtrl(ctx, s.cfg.socketPath, s.done)
		require.NoError(t, err)
		defer ctrl.Close()

		// Emulator::new: prepare_data_fd, probe_caps, get_established_flag
		data, err := ctrl.setDataFd()
		require.NoError(t, err, "CMD_SET_DATAFD after the shim's session")
		defer data.Close()
		_, err = ctrl.command(1, nil, -1, 8) // CMD_GET_CAPABILITY
		require.NoError(t, err)
		_, err = ctrl.command(4, nil, -1, 8) // CMD_GET_TPMESTABLISHED (needs a running TPM)
		require.NoError(t, err)
		// Tpm::reset: get_buffer_size -> set_buffer_size(0) (CMD_STOP first)
		_, err = ctrl.command(14, nil, -1, 4) // CMD_STOP
		require.NoError(t, err)
		_, err = ctrl.command(17, []byte{0, 0, 0, 0}, -1, 16) // CMD_SET_BUFFERSIZE 0
		require.NoError(t, err)
		// startup_tpm: set_buffer_size(n) (CMD_STOP first), CMD_INIT
		_, err = ctrl.command(14, nil, -1, 4)
		require.NoError(t, err)
		_, err = ctrl.command(17, []byte{0, 0, 0x0f, 0x80}, -1, 16) // 3968
		require.NoError(t, err)
		_, err = ctrl.command(2, []byte{0, 0, 0, 0}, -1, 4) // CMD_INIT flags=0
		require.NoError(t, err)

		// Guest kernel: TPM2_Startup(CLEAR) must succeed (TPM_RC_INITIALIZE
		// would mean the TPM was not freshly initialized).
		resp, err := tpmTransact(data, buildStartupClear())
		require.NoError(t, err)
		rc, err := tpmResponseCode(resp)
		require.NoError(t, err)
		assert.Equal(t, uint32(tpmRcSuccess), rc, "TPM2_Startup after CLH init")

		// Same TPM identity as the shim saw.
		fp, err := computeSrkFingerprint(data)
		require.NoError(t, err)
		assert.Equal(t, s.Fingerprint, fp)
	}

	clhAttachAndCheck()

	// swtpm dying after handoff fires onQuit exactly like virtiofsd.
	syscall.Kill(s.pid, syscall.SIGKILL)
	select {
	case <-quit:
	case <-time.After(5 * time.Second):
		t.Fatal("onQuit not called after swtpm died")
	}
	require.NoError(t, s.Stop(ctx))
	l, err := acquireSessionLock(ctx, s.cfg.stateDir, 300*time.Millisecond)
	require.NoError(t, err)
	l.Close()
}

// TestSwtpmIntegrationLockSharedWithChild: the session lock stays held as
// long as swtpm lives, even if the shim's own descriptor is gone.
func TestSwtpmIntegrationLockSharedWithChild(t *testing.T) {
	e := newSwtpmEnv(t)
	ctx := context.Background()

	s := newSwtpm(e.cfg(SeedTpmModeCreate, "s-ns-l", ""))
	require.NoError(t, s.Start(ctx))
	s.lockFile.Close() // as if the shim had dropped its fd
	s.lockFile = nil

	_, err := acquireSessionLock(ctx, s.cfg.stateDir, 300*time.Millisecond)
	assert.ErrorContains(t, err, "timed out", "swtpm must keep the lock")

	require.NoError(t, s.Stop(ctx))
	l, err := acquireSessionLock(ctx, s.cfg.stateDir, time.Second)
	require.NoError(t, err)
	l.Close()
}

// TestSwtpmIntegrationHandoffNeedsHangup is the negative control for the
// handoff: while the shim's data channel is still open, swtpm refuses a
// second CMD_SET_DATAFD, i.e. cloud-hypervisor could not attach.
func TestSwtpmIntegrationHandoffNeedsHangup(t *testing.T) {
	e := newSwtpmEnv(t)
	ctx := context.Background()

	s := newSwtpm(e.cfg(SeedTpmModeCreate, "s-ns-n", ""))
	require.NoError(t, s.Start(ctx))
	defer s.Stop(ctx)

	ctrl1, err := dialSwtpmCtrl(ctx, s.cfg.socketPath, s.done)
	require.NoError(t, err)
	data1, err := ctrl1.setDataFd()
	require.NoError(t, err)
	ctrl1.Close() // control closed, data channel still open

	ctrl2, err := dialSwtpmCtrl(ctx, s.cfg.socketPath, s.done)
	require.NoError(t, err)
	_, err = ctrl2.setDataFd()
	assert.Error(t, err, "second CMD_SET_DATAFD must fail while the first data fd is open")
	ctrl2.Close()

	data1.Close()
	ctrl3, err := dialSwtpmCtrl(ctx, s.cfg.socketPath, s.done)
	require.NoError(t, err)
	defer ctrl3.Close()
	// sync on the control channel, as swtpmFingerprint does
	_, err = ctrl3.command(swtpmCmdGetCapability, nil, -1, 8)
	require.NoError(t, err)
	d3, err := ctrl3.setDataFd()
	require.NoError(t, err, "CMD_SET_DATAFD after hangup")
	d3.Close()
}

func TestCheckSameFilesystem(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, ".seed-fs")
	require.NoError(t, os.WriteFile(sentinel, []byte("x"), 0644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "a"), 0755))
	assert.NoError(t, checkSameFilesystem(sentinel, filepath.Join(dir, "a")))

	var a, b unix.Stat_t
	if unix.Stat(dir, &a) != nil || unix.Stat("/dev/shm", &b) != nil || a.Dev == b.Dev {
		t.Skip("no second filesystem available")
	}
	assert.ErrorContains(t, checkSameFilesystem(sentinel, "/dev/shm"), "not on the same filesystem")
}

// TestSwtpmIntegrationShimKilled: SIGKILL the process that owns swtpm (a
// child running TestSwtpmHelperShim). Pdeathsig must take swtpm down and
// the session lock must then be free.
func TestSwtpmIntegrationShimKilled(t *testing.T) {
	e := newSwtpmEnv(t)
	stateDir := filepath.Join(e.root, "s-ns-k")

	cmd := exec.Command(os.Args[0], "-test.run=^TestSwtpmHelperShim$", "-test.v")
	cmd.Env = append(os.Environ(),
		"SEED_SWTPM_HELPER=1",
		"SEED_SWTPM_HELPER_ROOT="+e.root,
		"SEED_SWTPM_HELPER_RUN="+e.runDir)
	out, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	var swtpmPid int
	var buf []byte
	deadline := time.Now().Add(20 * time.Second)
	for swtpmPid == 0 && time.Now().Before(deadline) {
		chunk := make([]byte, 512)
		n, err := out.Read(chunk)
		buf = append(buf, chunk[:n]...)
		for _, line := range strings.Split(string(buf), "\n") {
			if strings.HasPrefix(line, "SWTPM_PID=") {
				fmt.Sscanf(line, "SWTPM_PID=%d", &swtpmPid)
			}
		}
		if err != nil {
			break
		}
	}
	require.True(t, swtpmPid > 0, "helper did not report a swtpm pid: %s", string(buf))
	assert.True(t, pidAlive(swtpmPid))

	// the "shim" dies hard
	cmd.Process.Kill()
	cmd.Wait()

	gone := false
	for i := 0; i < 100; i++ {
		if !pidAlive(swtpmPid) {
			gone = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.True(t, gone, "swtpm outlived its shim")

	l, err := acquireSessionLock(context.Background(), stateDir, 5*time.Second)
	require.NoError(t, err, "session lock not released after shim + swtpm died")
	l.Close()
}

// TestSwtpmPrintFingerprint prints the shim fingerprint of an existing TPM
// state dir (use a copy). Used to cross-check against tpm2-tools:
// SEED_FP_STATE_DIR=/copy/of/state go test -run TestSwtpmPrintFingerprint -v
func TestSwtpmPrintFingerprint(t *testing.T) {
	dir := os.Getenv("SEED_FP_STATE_DIR")
	bin := os.Getenv("SEED_TEST_SWTPM")
	if dir == "" || bin == "" {
		t.Skip("SEED_FP_STATE_DIR / SEED_TEST_SWTPM not set")
	}
	run, err := os.MkdirTemp("", "fp")
	require.NoError(t, err)
	defer os.RemoveAll(run)
	s := newSwtpm(swtpmConfig{
		path:        bin,
		mode:        SeedTpmModeVerify,
		stateDir:    dir,
		socketPath:  filepath.Join(run, "swtpm.sock"),
		volatileDir: filepath.Join(run, "vol"),
	})
	require.NoError(t, s.launch())
	defer s.Stop(context.Background())
	fp, err := swtpmFingerprint(context.Background(), s.cfg.socketPath, s.done)
	require.NoError(t, err)
	fmt.Printf("SHIM_FINGERPRINT=%s\n", fp)
}

// TestSwtpmHoldForCLH runs the shim side (Start) and keeps swtpm up until
// <run>/release exists, so a real cloud-hypervisor can attach in between.
// Manual end-to-end helper; skipped unless SEED_HOLD_ROOT is set.
func TestSwtpmHoldForCLH(t *testing.T) {
	root := os.Getenv("SEED_HOLD_ROOT")
	if root == "" {
		t.Skip("SEED_HOLD_ROOT not set")
	}
	e := &swtpmEnv{
		root:    root,
		runDir:  os.Getenv("SEED_HOLD_RUN"),
		swtpm:   os.Getenv("SEED_TEST_SWTPM"),
		fsid:    "58ec6b96-5df6-49f2-86c3-182501b0602d",
		timeout: 5 * time.Second,
	}
	s := newSwtpm(e.cfg(os.Getenv("SEED_HOLD_MODE"), "s-ns-clh", os.Getenv("SEED_HOLD_FP")))
	require.NoError(t, s.Start(context.Background()))
	fmt.Printf("SHIM_FINGERPRINT=%s\nSOCKET=%s\n", s.Fingerprint, s.cfg.socketPath)
	os.Stdout.Sync()
	quit := make(chan struct{})
	s.arm(func() { close(quit) })
	for {
		if _, err := os.Stat(filepath.Join(e.runDir, "release")); err == nil {
			break
		}
		select {
		case <-quit:
			t.Fatal("swtpm died while held")
		case <-time.After(100 * time.Millisecond):
		}
	}
	require.NoError(t, s.Stop(context.Background()))
	fmt.Println("STOPPED")
}

// TestSwtpmHelperShim is not a real test: it is the child process for
// TestSwtpmIntegrationShimKilled.
func TestSwtpmHelperShim(t *testing.T) {
	if os.Getenv("SEED_SWTPM_HELPER") != "1" {
		t.Skip("helper process only")
	}
	e := &swtpmEnv{
		root:    os.Getenv("SEED_SWTPM_HELPER_ROOT"),
		runDir:  os.Getenv("SEED_SWTPM_HELPER_RUN"),
		swtpm:   os.Getenv("SEED_TEST_SWTPM"),
		fsid:    "58ec6b96-5df6-49f2-86c3-182501b0602d",
		timeout: time.Second,
	}
	s := newSwtpm(e.cfg(SeedTpmModeCreate, "s-ns-k", ""))
	if err := s.Start(context.Background()); err != nil {
		fmt.Printf("START_ERROR=%v\n", err)
		os.Exit(1)
	}
	// Extra goroutines so the runtime has several threads around.
	for i := 0; i < 8; i++ {
		go func() { time.Sleep(time.Hour) }()
	}
	fmt.Printf("SWTPM_PID=%d\n", s.pid)
	os.Stdout.Sync()
	select {}
}
