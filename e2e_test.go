package cloudiso_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cloudiso "github.com/pilat/cloudiso"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// dockerImage pins Alpine 3.19 whose cdrkit package is genisoimage 1.1.11,
	// the byte-match oracle.
	dockerImage        = "alpine:3.19"
	sharedContainerDir = "/iso-images"
	// noatimeTmpfsDir is a tmpfs mount point inside the container, created once
	// by startDockerContainer with the noatime option. The byte-match harness
	// copies input trees here so that genisoimage's opendir/readdir calls do not
	// update st_atime on the input files.
	noatimeTmpfsDir = "/iso-noatime"
)

// =============================================================================
// Package State
// =============================================================================

var (
	dockerContainerID string
	dockerAvailable   bool
	sharedHostDir     string
	cdrkitVersionInfo string
)

// =============================================================================
// TestMain
// =============================================================================

// TestMain sets up a single long-lived Docker container reused by all e2e tests.
// Unit tests in the same package always run; each e2e test calls skipIfNoDocker
// to opt out cleanly when Docker is absent.
func TestMain(m *testing.M) {
	if err := exec.Command("docker", "info").Run(); err == nil {
		dockerAvailable = true

		dir, err := os.MkdirTemp("", "goisofs-e2e-")
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to create shared host dir:", err)
			os.Exit(1)
		}
		sharedHostDir = dir

		id, err := startDockerContainer()
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to start Docker container:", err)
			_ = os.RemoveAll(sharedHostDir)
			os.Exit(1)
		}
		dockerContainerID = strings.TrimSpace(id)
		if cdrkitVersionInfo != "" {
			fmt.Fprintln(os.Stderr, "e2e oracle:", cdrkitVersionInfo)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Docker not available, e2e tests will skip")
	}

	code := m.Run()

	if dockerContainerID != "" {
		stopDockerContainer(dockerContainerID)
	}
	if sharedHostDir != "" {
		_ = os.RemoveAll(sharedHostDir)
	}

	os.Exit(code)
}

// =============================================================================
// Tests
// =============================================================================

// TestMountNoCloud builds a NoCloud cidata ISO and mounts it in the container.
// Verifies volume label, file permissions (444/555), ownership (0:0), and
// exact file names (no UPPERCASE mangling). Contents must be byte-identical.
func TestMountNoCloud(t *testing.T) {
	skipIfNoDocker(t)

	const volID = "cidata"
	const pub = "cloudiso"

	fixed := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	env := newTestEnv(t, volID, pub, fixed)

	require.NoError(t, env.writer.AddDir("/", fixed))
	require.NoError(t, env.writer.AddFile("meta-data", []byte("instance-id: test-001\nlocal-hostname: goisofs-test\n"), fixed))
	require.NoError(t, env.writer.AddFile("user-data", []byte("#cloud-config\nruncmd:\n  - echo hi\n"), fixed))
	require.NoError(t, env.writer.AddFile("network-config", []byte("version: 2\nethernets:\n  eth0:\n    dhcp4: true\n"), fixed))

	env.finalize(t)

	// isoinfo does not need the ISO mounted; run it outside buildMountScript.
	isoPath := sharedContainerDir + "/" + filepath.Base(env.imagePath)
	label := execInContainer(t, fmt.Sprintf("isoinfo -d -i %s | grep 'Volume id'", isoPath))
	assert.Contains(t, label, "Volume id: cidata")

	out := env.dockerExecSimple(t,
		// paths are relative to mountDir because buildMountScript does cd $mountDir
		`stat -c '%a %u:%g %n' meta-data`,
		`stat -c '%a %u:%g %n' user-data`,
		`stat -c '%a %u:%g %n' network-config`,
		`cat meta-data`,
		`cat user-data`,
		`cat network-config`,
	)

	assert.Contains(t, out, "444 0:0")
	assert.Contains(t, out, "meta-data")
	assert.Contains(t, out, "user-data")
	assert.Contains(t, out, "network-config")
	assert.Contains(t, out, "instance-id: test-001")
	assert.Contains(t, out, "#cloud-config")
	assert.Contains(t, out, "version: 2")
}

// TestMountConfigDrive builds an OpenStack ConfigDrive v2 ISO (config-2) and
// verifies that nested paths survive the round-trip with correct names and content.
func TestMountConfigDrive(t *testing.T) {
	skipIfNoDocker(t)

	fixed := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	env := newTestEnv(t, "config-2", "cloudiso", fixed)

	require.NoError(t, env.writer.AddDir("/", fixed))
	require.NoError(t, env.writer.AddDir("openstack", fixed))
	require.NoError(t, env.writer.AddDir("openstack/latest", fixed))
	require.NoError(t, env.writer.AddDir("ec2", fixed))
	require.NoError(t, env.writer.AddDir("ec2/latest", fixed))
	require.NoError(t, env.writer.AddFile("openstack/latest/meta_data.json", []byte(`{"uuid":"abc-123"}`), fixed))
	require.NoError(t, env.writer.AddFile("openstack/latest/user_data", []byte("#!/bin/bash\necho hello\n"), fixed))
	require.NoError(t, env.writer.AddFile("ec2/latest/meta-data.json", []byte(`{"instance-id":"abc-123"}`), fixed))

	env.finalize(t)

	isoPath := sharedContainerDir + "/" + filepath.Base(env.imagePath)
	label := execInContainer(t, fmt.Sprintf("isoinfo -d -i %s | grep 'Volume id'", isoPath))
	assert.Contains(t, label, "Volume id: config-2")

	out := env.dockerExecSimple(t,
		`stat -c '%a %u:%g %n' openstack`,
		`stat -c '%a %u:%g %n' openstack/latest`,
		`stat -c '%a %u:%g %n' openstack/latest/meta_data.json`,
		`cat openstack/latest/meta_data.json`,
		`cat openstack/latest/user_data`,
		`cat ec2/latest/meta-data.json`,
	)

	assert.Contains(t, out, "555 0:0")
	assert.Contains(t, out, "openstack")
	assert.Contains(t, out, "444 0:0")
	assert.Contains(t, out, "meta_data.json")
	assert.Contains(t, out, `{"uuid":"abc-123"}`)
	assert.Contains(t, out, "#!/bin/bash")
	assert.Contains(t, out, `{"instance-id":"abc-123"}`)
}

// TestLongNames verifies files with max-length (30-char) names and names
// containing multi-dot / leading-dot / hyphen / underscore survive the round-trip.
func TestLongNames(t *testing.T) {
	skipIfNoDocker(t)

	name30 := strings.Repeat("a", 30)

	fixed := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	env := newTestEnv(t, "cidata", "cloudiso", fixed)

	require.NoError(t, env.writer.AddDir("/", fixed))
	require.NoError(t, env.writer.AddFile("meta-data", []byte("md"), fixed))
	require.NoError(t, env.writer.AddFile("a.b.c", []byte("dotted"), fixed))
	require.NoError(t, env.writer.AddFile(".hidden", []byte("hidden"), fixed))
	require.NoError(t, env.writer.AddFile("user_data", []byte("ud"), fixed))
	require.NoError(t, env.writer.AddFile(name30, []byte("max30"), fixed))

	env.finalize(t)

	out := env.dockerExecSimple(t,
		`test -f meta-data && echo "meta-data ok"`,
		`test -f a.b.c && echo "a.b.c ok"`,
		`test -f .hidden && echo ".hidden ok"`,
		`test -f user_data && echo "user_data ok"`,
		fmt.Sprintf(`test -f %s && echo "name30 ok"`, name30),
		`cat a.b.c`,
		`cat .hidden`,
		`cat user_data`,
	)

	assert.Contains(t, out, "meta-data ok")
	assert.Contains(t, out, "a.b.c ok")
	assert.Contains(t, out, ".hidden ok")
	assert.Contains(t, out, "user_data ok")
	assert.Contains(t, out, "name30 ok")
	assert.Contains(t, out, "dotted")
	assert.Contains(t, out, "hidden")
	assert.Contains(t, out, "ud")
}

// TestDiffWithGenisoimage is the key diff test. It builds the same input tree
// both via our Writer and via genisoimage -J -r, then mounts both ISOs and
// compares the file listing and contents.
//
// Known / justified divergences are documented inline.
func TestDiffWithGenisoimage(t *testing.T) {
	skipIfNoDocker(t)

	// Input tree: flat files with cloud-init-shaped names.
	type inputFile struct {
		path    string
		content []byte
	}
	inputs := []inputFile{
		{"meta-data", []byte("instance-id: test-001\nlocal-hostname: goisofs-test\n")},
		{"user-data", []byte("#cloud-config\nruncmd:\n  - echo hi\n")},
		{"network-config", []byte("version: 2\nethernets:\n  eth0:\n    dhcp4: true\n")},
	}

	const volID = "cidata"
	const pub = "cloudiso"
	fixed := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	// --- Build ours.iso ---
	env := newTestEnv(t, volID, pub, fixed)
	require.NoError(t, env.writer.AddDir("/", fixed))
	for _, f := range inputs {
		require.NoError(t, env.writer.AddFile(f.path, f.content, fixed))
	}
	env.finalize(t)
	oursName := filepath.Base(env.imagePath)

	// --- Populate input dir in shared host dir for genisoimage ---
	inputDirHost := filepath.Join(sharedHostDir, fmt.Sprintf("input-%d", time.Now().UnixNano()))
	require.NoError(t, os.MkdirAll(inputDirHost, 0o755))
	for _, f := range inputs {
		require.NoError(t, os.WriteFile(filepath.Join(inputDirHost, f.path), f.content, 0o644))
	}
	inputDirContainer := sharedContainerDir + "/" + filepath.Base(inputDirHost)

	theirs := env.runGenisoimage(t, inputDirContainer, "theirs.iso", volID, pub)
	_ = theirs

	oursMount := fmt.Sprintf("/mnt/ours-%d", time.Now().UnixNano())
	theirsMount := fmt.Sprintf("/mnt/theirs-%d", time.Now().UnixNano())
	oursPath := sharedContainerDir + "/" + oursName
	theirsPath := sharedContainerDir + "/theirs.iso"

	// Collect ls -1 sorted listings from both mounts (no timestamps, no sizes).
	// Then diff them. Use mount -t iso9660 -o loop,ro so Rock Ridge is used by default.
	script := fmt.Sprintf(`
set -e
mkdir -p %[1]s %[2]s

cleanup() {
    umount %[1]s 2>/dev/null || umount -l %[1]s 2>/dev/null || true
    umount %[2]s 2>/dev/null || umount -l %[2]s 2>/dev/null || true
}
trap cleanup EXIT

mount -t iso9660 -o loop,ro %[3]s %[1]s
mount -t iso9660 -o loop,ro %[4]s %[2]s

echo "=== OURS ls ==="
ls -1 %[1]s | sort

echo "=== THEIRS ls ==="
ls -1 %[2]s | sort

echo "=== OURS stat ==="
for f in %[1]s/*; do
    stat -c '%%a %%u:%%g %%s %%n' "$f"
done

echo "=== THEIRS stat ==="
for f in %[2]s/*; do
    stat -c '%%a %%u:%%g %%s %%n' "$f"
done

echo "=== OURS cat meta-data ==="
cat %[1]s/meta-data

echo "=== THEIRS cat meta-data ==="
cat %[2]s/meta-data

echo "=== OURS cat user-data ==="
cat %[1]s/user-data

echo "=== THEIRS cat user-data ==="
cat %[2]s/user-data

echo "=== OURS cat network-config ==="
cat %[1]s/network-config

echo "=== THEIRS cat network-config ==="
cat %[2]s/network-config
`, oursMount, theirsMount, oursPath, theirsPath)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", "--privileged", dockerContainerID, "sh", "-c", script)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	require.NoError(t, err, "diff script failed\nstdout: %s\nstderr: %s", stdoutBuf.String(), stderrBuf.String())

	out := stdoutBuf.String()
	t.Logf("diff output:\n%s", out)

	// Extract sections.
	oursLS := extractSection(out, "=== OURS ls ===", "===")
	theirsLS := extractSection(out, "=== THEIRS ls ===", "===")

	// Divergence: genisoimage without -T does NOT create TRANS.TBL.
	// Both trees should have the same files. Strip trailing whitespace for comparison.
	oursFiles := strings.Fields(oursLS)
	theirsFiles := strings.Fields(theirsLS)

	assert.Equal(t, oursFiles, theirsFiles, "file listing mismatch between ours and genisoimage")

	// Stat section: compare mode, uid:gid, size, and base name.
	// Strip the mount-point prefix before comparing.
	oursStat := normalizeStatOutput(extractSection(out, "=== OURS stat ===", "==="), oursMount)
	theirsStat := normalizeStatOutput(extractSection(out, "=== THEIRS stat ===", "==="), theirsMount)
	assert.Equal(t, oursStat, theirsStat, "stat mismatch between ours and genisoimage")

	// Content equality for each file.
	for _, name := range []string{"meta-data", "user-data", "network-config"} {
		oursContent := extractSection(out, "=== OURS cat "+name+" ===", "===")
		theirsContent := extractSection(out, "=== THEIRS cat "+name+" ===", "===")
		assert.Equal(t, oursContent, theirsContent, "content mismatch for %s", name)
	}
}

// TestDiffWithGenisoimageNested mirrors TestDiffWithGenisoimage but for a
// nested ConfigDrive-shaped tree. The flat and nested tests live side by side
// so a regression in either depth localizes cleanly.
func TestDiffWithGenisoimageNested(t *testing.T) {
	skipIfNoDocker(t)

	type inputFile struct {
		path    string
		content []byte
	}
	inputs := []inputFile{
		{"openstack/latest/meta_data.json", []byte(`{"uuid":"test-001"}`)},
		{"openstack/latest/user_data", []byte("#cloud-config\n")},
		{"openstack/latest/vendor_data.json", []byte("{}")},
		{"ec2/latest/meta-data.json", []byte(`{"instance-id":"i-0001"}`)},
		{"meta-data", []byte("instance-id: test-001\n")},
	}

	const volID = "config-2"
	const pub = "cloudiso"
	fixed := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	env := newTestEnv(t, volID, pub, fixed)
	require.NoError(t, env.writer.AddDir("/", fixed))
	require.NoError(t, env.writer.AddDir("openstack", fixed))
	require.NoError(t, env.writer.AddDir("openstack/latest", fixed))
	require.NoError(t, env.writer.AddDir("ec2", fixed))
	require.NoError(t, env.writer.AddDir("ec2/latest", fixed))
	for _, f := range inputs {
		require.NoError(t, env.writer.AddFile(f.path, f.content, fixed))
	}
	env.finalize(t)
	oursName := filepath.Base(env.imagePath)

	inputDirHost := filepath.Join(sharedHostDir, fmt.Sprintf("input-nested-%d", time.Now().UnixNano()))
	for _, f := range inputs {
		dst := filepath.Join(inputDirHost, f.path)
		require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
		require.NoError(t, os.WriteFile(dst, f.content, 0o644))
	}
	inputDirContainer := sharedContainerDir + "/" + filepath.Base(inputDirHost)

	_ = env.runGenisoimage(t, inputDirContainer, "theirs-nested.iso", volID, pub)

	oursMount := fmt.Sprintf("/mnt/ours-nested-%d", time.Now().UnixNano())
	theirsMount := fmt.Sprintf("/mnt/theirs-nested-%d", time.Now().UnixNano())
	oursPath := sharedContainerDir + "/" + oursName
	theirsPath := sharedContainerDir + "/theirs-nested.iso"

	// `cd $mount` before find so %n yields relative paths identical between
	// the two mounts. Subshells keep each section's working directory local.
	script := fmt.Sprintf(`
set -e
mkdir -p %[1]s %[2]s

cleanup() {
    umount %[1]s 2>/dev/null || umount -l %[1]s 2>/dev/null || true
    umount %[2]s 2>/dev/null || umount -l %[2]s 2>/dev/null || true
}
trap cleanup EXIT

mount -t iso9660 -o loop,ro %[3]s %[1]s
mount -t iso9660 -o loop,ro %[4]s %[2]s

echo "=== OURS files ==="
(cd %[1]s && find . -type f | sort)

echo "=== THEIRS files ==="
(cd %[2]s && find . -type f | sort)

echo "=== OURS stat ==="
(cd %[1]s && find . -type f | sort | while read -r f; do
    stat -c '%%a %%u:%%g %%s %%n' "$f"
done)

echo "=== THEIRS stat ==="
(cd %[2]s && find . -type f | sort | while read -r f; do
    stat -c '%%a %%u:%%g %%s %%n' "$f"
done)

echo "=== OURS content ==="
(cd %[1]s && find . -type f | sort | while read -r f; do
    echo "--- $f ---"
    cat "$f"
    echo
done)

echo "=== THEIRS content ==="
(cd %[2]s && find . -type f | sort | while read -r f; do
    echo "--- $f ---"
    cat "$f"
    echo
done)
`, oursMount, theirsMount, oursPath, theirsPath)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", "--privileged", dockerContainerID, "sh", "-c", script)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	require.NoError(t, err, "diff script failed\nstdout: %s\nstderr: %s", stdoutBuf.String(), stderrBuf.String())

	out := stdoutBuf.String()
	t.Logf("diff output:\n%s", out)

	oursLS := extractSection(out, "=== OURS files ===", "===")
	theirsLS := extractSection(out, "=== THEIRS files ===", "===")
	assert.Equal(t, strings.Fields(oursLS), strings.Fields(theirsLS),
		"file listing mismatch (nested)")

	// Empty mount prefix because find paths are already relative ("./foo/bar").
	oursStat := normalizeStatOutput(extractSection(out, "=== OURS stat ===", "==="), "")
	theirsStat := normalizeStatOutput(extractSection(out, "=== THEIRS stat ===", "==="), "")
	assert.Equal(t, oursStat, theirsStat, "stat mismatch (nested)")

	oursContent := extractSection(out, "=== OURS content ===", "===")
	theirsContent := extractSection(out, "=== THEIRS content ===", "===")
	assert.Equal(t, oursContent, theirsContent, "content mismatch (nested)")
}

// =============================================================================
// Test Infrastructure
// =============================================================================

// testEnv encapsulates resources for a single e2e test.
type testEnv struct {
	imagePath string
	writer    *cloudiso.Writer
}

// newTestEnv creates a Writer and an image path in the shared dir.
func newTestEnv(t *testing.T, volumeID, publisher string, creationTime time.Time) *testEnv {
	t.Helper()
	require.NotEmpty(t, sharedHostDir, "sharedHostDir must be initialized in TestMain")

	imagePath := filepath.Join(sharedHostDir, fmt.Sprintf("test-%d.iso", time.Now().UnixNano()))

	w := &cloudiso.Writer{
		VolumeID:     volumeID,
		Publisher:    publisher,
		CreationTime: creationTime,
	}
	return &testEnv{
		imagePath: imagePath,
		writer:    w,
	}
}

// finalize calls w.Write into the image file.
func (e *testEnv) finalize(t *testing.T) {
	t.Helper()

	f, err := os.Create(e.imagePath)
	require.NoError(t, err, "create image file")

	err = e.writer.Write(f)
	_ = f.Close()
	require.NoError(t, err, "write ISO")
}

// dockerExec runs commands inside the container, mounting the ISO first.
// Returns stdout, stderr, and the error.
func (e *testEnv) dockerExec(t *testing.T, commands ...string) (stdout, stderr string, err error) {
	t.Helper()

	if !dockerAvailable || dockerContainerID == "" {
		return "", "", fmt.Errorf("docker test container not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	remoteImage := filepath.Join(sharedContainerDir, filepath.Base(e.imagePath))
	mountDir := fmt.Sprintf("/mnt/iso-%d", time.Now().UnixNano())

	script := buildMountScript(remoteImage, mountDir, commands)

	cmd := exec.CommandContext(ctx, "docker", "exec", "--privileged", dockerContainerID, "sh", "-c", script)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		return stdoutBuf.String(), stderrBuf.String(), fmt.Errorf("docker exec timed out after 60s")
	}

	return stdoutBuf.String(), stderrBuf.String(), err
}

// dockerExecSimple runs commands and fails the test on any error.
func (e *testEnv) dockerExecSimple(t *testing.T, commands ...string) string {
	t.Helper()

	stdout, stderr, err := e.dockerExec(t, commands...)
	if err != nil {
		t.Fatalf("docker exec failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	return stdout
}

// runGenisoimage runs genisoimage inside the container on the given input dir
// and returns the container path of the output ISO.
func (e *testEnv) runGenisoimage(t *testing.T, inputDir, outputName, volID, publisher string) string {
	t.Helper()

	outPath := sharedContainerDir + "/" + outputName

	// Use flags that align our Writer's PVD/SVD text fields with genisoimage's output:
	//   -J        Joliet extension
	//   -r        Rock Ridge (rationalized: uid=0/gid=0/0444/0555)
	//   -V        volume ID
	//   -publisher publisher field
	//   -preparer publisher field (we use same value)
	//   -appid    application identifier (matches our "CLOUDISO")
	//   -sysid '' empty system identifier (matches our space-padded empty)
	// No -T: we don't emit TRANS.TBL and genisoimage won't either without -T.
	script := fmt.Sprintf(
		`genisoimage -J -r -V %s -publisher %s -preparer %s -appid CLOUDISO -sysid '' -o %s %s 2>/dev/null`,
		shellescape(volID),
		shellescape(publisher),
		shellescape(publisher),
		shellescape(outPath),
		shellescape(inputDir),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", dockerContainerID, "sh", "-c", script)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	require.NoError(t, err, "genisoimage failed\nstdout: %s\nstderr: %s", stdoutBuf.String(), stderrBuf.String())

	return outPath
}

// =============================================================================
// Docker Container Management
// =============================================================================

func startDockerContainer() (string, error) {
	volumeArg := fmt.Sprintf("%s:%s", sharedHostDir, sharedContainerDir)

	cmd := exec.Command(
		"docker", "run", "-d", "--privileged", "-v", volumeArg, dockerImage,
		"sleep", "infinity",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker run failed: %w (stderr: %s)", err, stderr.String())
	}

	containerID := strings.TrimSpace(stdout.String())

	installCmd := exec.Command(
		"docker", "exec", containerID,
		"apk", "add", "--no-cache", "cdrkit", "coreutils", "libfaketime",
	)

	if err := installCmd.Run(); err != nil {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
		return "", fmt.Errorf("failed to install packages: %w", err)
	}

	// Mount a tmpfs with noatime for use by the byte-match harness. The
	// noatime option prevents genisoimage's directory reads from updating
	// st_atime on the input files, which would make TF ACCESS timestamps
	// diverge from the pinned mtime values.
	setupCmd := exec.Command(
		"docker", "exec", containerID,
		"sh", "-c",
		fmt.Sprintf("mkdir -p %s && mount -t tmpfs -o noatime tmpfs %s", noatimeTmpfsDir, noatimeTmpfsDir),
	)
	if err := setupCmd.Run(); err != nil {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
		return "", fmt.Errorf("failed to mount noatime tmpfs: %w", err)
	}

	versionInfo, err := detectCdrkitVersion(containerID)
	if err != nil {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
		return "", fmt.Errorf("failed to detect cdrkit/genisoimage version: %w", err)
	}
	if !strings.Contains(versionInfo, "1.1.11") {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
		return "", fmt.Errorf("unsupported genisoimage/cdrkit version in test container: %s", versionInfo)
	}
	cdrkitVersionInfo = versionInfo

	return containerID, nil
}

func detectCdrkitVersion(containerID string) (string, error) {
	cmd := exec.Command(
		"docker", "exec", containerID,
		"sh", "-lc",
		"set -e; genisoimage --version 2>&1 | head -n 1; apk info cdrkit | head -n 1",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("detect cdrkit version: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func stopDockerContainer(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_ = exec.CommandContext(ctx, "docker", "stop", "-t", "5", id).Run()
	_ = exec.CommandContext(ctx, "docker", "rm", id).Run()
}

func skipIfNoDocker(t *testing.T) {
	t.Helper()

	if !dockerAvailable || dockerContainerID == "" {
		t.Skip("Docker test container not available, skipping e2e test")
	}
}

// =============================================================================
// Script Builder
// =============================================================================

// buildMountScript mounts the ISO at mountDir, runs commands, then unmounts.
// Uses -o loop,ro (Rock Ridge auto-selected by the kernel).
func buildMountScript(imagePath, mountDir string, commands []string) string {
	return fmt.Sprintf(`
set -e

mkdir -p %[2]s

cleanup() {
    umount %[2]s 2>/dev/null || umount -l %[2]s 2>/dev/null || true
}
trap cleanup EXIT

mount -t iso9660 -o loop,ro %[1]s %[2]s

cd %[2]s
%[3]s
`, imagePath, mountDir, strings.Join(commands, "\n"))
}

// =============================================================================
// Helpers
// =============================================================================

// execInContainer runs a single shell command in the container without mounting
// any ISO. Used for isoinfo queries that don't need the image mounted.
func execInContainer(t *testing.T, script string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "exec", dockerContainerID, "sh", "-c", script)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("execInContainer failed: %v\noutput: %s", err, out.String())
	}
	return out.String()
}

// extractSection returns the trimmed text between the line containing start and
// the next line containing stop (exclusive of both marker lines).
func extractSection(output, start, stop string) string {
	lines := strings.Split(output, "\n")
	var result []string
	inside := false
	for _, line := range lines {
		if !inside {
			if strings.Contains(line, start) {
				inside = true
			}
			continue
		}
		if strings.Contains(line, stop) {
			break
		}
		result = append(result, line)
	}
	// Trim trailing empty lines so sections without a following "===" don't get an extra newline.
	for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
		result = result[:len(result)-1]
	}
	return strings.Join(result, "\n")
}

// normalizeStatOutput strips the mount point prefix from stat output lines
// so ours and theirs can be compared without path differences.
func normalizeStatOutput(raw, mountPrefix string) string {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	normalized := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// stat -c '%a %u:%g %s %n' — last field is the path; strip prefix.
		parts := strings.SplitN(line, " ", 4)
		if len(parts) == 4 {
			name := strings.TrimPrefix(parts[3], mountPrefix+"/")
			normalized = append(normalized, fmt.Sprintf("%s %s %s %s", parts[0], parts[1], parts[2], name))
		} else {
			normalized = append(normalized, line)
		}
	}
	return strings.Join(normalized, "\n")
}

// shellescape wraps a string in single quotes for shell use.
// It does not handle values containing single quotes (not needed here).
func shellescape(s string) string {
	return "'" + s + "'"
}
