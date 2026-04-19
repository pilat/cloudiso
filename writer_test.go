package cloudiso_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/pilat/cloudiso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoundTrip writes an ISO with cloud-init-shaped names, then walks the
// primary tree directly via the on-disk dir records, asserting exact name
// preservation (no mangling) and content equality.
func TestRoundTrip(t *testing.T) {
	fixed := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)

	w := &cloudiso.Writer{
		VolumeID:     "cidata",
		Publisher:    "cloudiso",
		CreationTime: fixed,
	}

	require.NoError(t, w.AddDir("/", fixed))
	require.NoError(t, w.AddFile("meta-data", []byte("id"), fixed))
	require.NoError(t, w.AddFile("user-data", []byte("ud"), fixed))
	require.NoError(t, w.AddFile("network-config", []byte("nc"), fixed))
	require.NoError(t, w.AddDir("openstack", fixed))
	require.NoError(t, w.AddDir("openstack/latest", fixed))
	require.NoError(t, w.AddFile("openstack/latest/meta_data.json", []byte(`{}`), fixed))
	require.NoError(t, w.AddFile("openstack/latest/user_data", []byte("ud2"), fixed))

	var buf bytes.Buffer
	require.NoError(t, w.Write(&buf))
	bs := buf.Bytes()

	require.Equal(t, 0, len(bs)%2048, "image size must be multiple of 2048")

	assert.Equal(t, "cidata", readVolumeID(bs))

	want := map[string][]byte{
		"/meta-data":                       []byte("id"),
		"/user-data":                       []byte("ud"),
		"/network-config":                  []byte("nc"),
		"/openstack/latest/meta_data.json": []byte(`{}`),
		"/openstack/latest/user_data":      []byte("ud2"),
	}
	got := allPrimaryFiles(t, bs)
	assert.Equal(t, want, got)
}

// TestValidateName exercises names.validate via AddFile.
func TestValidateName(t *testing.T) {
	type tc struct {
		name  string
		isDir bool
		valid bool
	}

	// 30-char boundary case.
	name30 := strings.Repeat("a", 30)
	// 31-char name (genisoimage -l limit).
	name31 := strings.Repeat("a", 31)

	cases := []tc{
		// Valid: basic lowercase.
		{name: "abc", isDir: false, valid: true},
		// Valid: hyphen-separated (cloud-init style).
		{name: "meta-data", isDir: false, valid: true},
		// Valid: underscore.
		{name: "user_data", isDir: false, valid: true},
		// Valid: multi-component with dots.
		{name: "meta_data.json", isDir: false, valid: true},
		// Valid: leading dot.
		{name: ".hidden", isDir: false, valid: true},
		// Valid: multiple consecutive dots (multi-dot allowed).
		{name: "a..b.c", isDir: false, valid: true},
		// Valid: single character.
		{name: "a", isDir: false, valid: true},
		// Valid: 30-character name (at limit).
		{name: name30, isDir: false, valid: true},
		// Valid: uppercase still allowed.
		{name: "UPPER", isDir: false, valid: true},
		// Valid: mixed case.
		{name: "network-config", isDir: false, valid: true},
		// Valid: dir with permissive name.
		{name: "openstack", isDir: true, valid: true},
		// Valid: 31-character name (genisoimage -l limit).
		{name: name31, isDir: false, valid: true},
		// Invalid: space character.
		{name: "A B", isDir: false, valid: false},
		// Invalid: null byte.
		{name: "a\x00b", isDir: false, valid: false},
		// Invalid: question mark.
		{name: "a?b", isDir: false, valid: false},
		// Invalid: reserved name dot.
		{name: ".", isDir: false, valid: false},
		// Invalid: reserved name dotdot.
		{name: "..", isDir: false, valid: false},
		// Invalid: reserved name dotdot as dir component.
		{name: "..", isDir: true, valid: false},
		// Invalid: dash-only name — actually valid (hyphen is allowed).
		{name: "-", isDir: false, valid: true},
	}

	fixed := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &cloudiso.Writer{VolumeID: "TEST"}
			require.NoError(t, w.AddDir("/", fixed))

			var err error
			if tc.isDir {
				// For dot/dotdot tests use the name directly — they must fail
				// validation before even reaching the dir insertion logic.
				if tc.name == "." || tc.name == ".." {
					err = w.AddDir(tc.name, fixed)
				} else {
					// Register the dir, then a file inside it to confirm it's valid.
					err = w.AddDir(tc.name, fixed)
					if err == nil {
						err = w.AddFile(tc.name+"/f", []byte("x"), fixed)
					}
				}
			} else {
				err = w.AddFile(tc.name, []byte("x"), fixed)
			}

			if tc.valid && err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
			if !tc.valid && err == nil {
				t.Errorf("expected error for %q, got nil", tc.name)
			}
		})
	}
}

// dirEntry holds the LBA and dataSize parsed from a primary directory record.
type dirEntry struct {
	name     string
	lba      uint32
	dataSize uint32
	isDir    bool
}

// parsePrimaryRootEntries reads the PVD at sector 16, follows the root LBA,
// and parses all dir records (skipping dot/dotdot). Returns the entries in
// on-disk order. The version suffix ";1" is stripped from file identifiers.
func parsePrimaryRootEntries(t *testing.T, iso []byte) []dirEntry {
	t.Helper()
	const sectorSize = 2048
	pvd := iso[16*sectorSize : 17*sectorSize]
	// Root dir record at offset 156, LBA at +2 LE, size at +10 LE.
	rootRec := pvd[156:190]
	rootLBA := binary.LittleEndian.Uint32(rootRec[2:6])
	rootSize := binary.LittleEndian.Uint32(rootRec[10:14])
	require.NotZero(t, rootLBA, "primary root LBA must be non-zero")
	require.Equal(t, uint32(sectorSize), rootSize, "primary root size must be one sector")

	rootExtent := iso[rootLBA*sectorSize : rootLBA*sectorSize+rootSize]
	return parseDirRecords(t, rootExtent, true)
}

// parseDirRecords iterates dir records in extent. If skipDotDotdot is true,
// the first two records (dot, dotdot) are skipped.
//
// The entry name is resolved using the Rock Ridge NM record when present
// (preserving the original filename with hyphens etc.), otherwise falls back
// to the ISO 9660 primary FI with ";1" and a trailing separator dot stripped.
func parseDirRecords(t *testing.T, extent []byte, skipDotDotdot bool) []dirEntry {
	t.Helper()
	var out []dirEntry
	off := 0
	idx := 0
	for off < len(extent) {
		lenDR := int(extent[off])
		if lenDR == 0 {
			off = ((off / 2048) + 1) * 2048
			if off >= len(extent) {
				break
			}
			continue
		}
		if skipDotDotdot && idx < 2 {
			idx++
			off += lenDR
			continue
		}
		idx++
		rec := extent[off : off+lenDR]
		lba := binary.LittleEndian.Uint32(rec[2:6])
		size := binary.LittleEndian.Uint32(rec[10:14])
		flags := rec[25]
		lenFI := int(rec[32])
		ident := string(rec[33 : 33+lenFI])

		// Prefer the NM (Rock Ridge alternate name) record if present.
		name := rrNMName(rec, lenFI)
		if name == "" {
			// Fall back to ISO FI: strip ";1" and trailing separator dot.
			name = strings.TrimSuffix(ident, ";1")
			name = strings.TrimSuffix(name, ".")
		}

		out = append(out, dirEntry{
			name:     name,
			lba:      lba,
			dataSize: size,
			isDir:    flags&0x02 != 0,
		})
		off += lenDR
	}
	return out
}

// rrNMName extracts the filename from a Rock Ridge NM record in the SU area of
// a directory record. Returns "" if no NM record is found.
func rrNMName(rec []byte, lenFI int) string {
	// SU area starts at: 33 + lenFI + idPad (0 or 1).
	idPad := (33 + lenFI) % 2
	suOff := 33 + lenFI + idPad
	lenDR := int(rec[0])
	if suOff >= lenDR {
		return ""
	}
	su := rec[suOff:lenDR]
	for i := 0; i+4 <= len(su); {
		if su[i] == 0 {
			break
		}
		recLen := int(su[i+2])
		if recLen < 4 || i+recLen > len(su) {
			break
		}
		if su[i] == 'N' && su[i+1] == 'M' && recLen >= 5 {
			return string(su[i+5 : i+recLen])
		}
		i += recLen
	}
	return ""
}

// findEntry returns the entry whose name matches, failing the test if missing.
func findEntry(t *testing.T, entries []dirEntry, name string) dirEntry {
	t.Helper()
	for _, e := range entries {
		if e.name == name {
			return e
		}
	}
	t.Fatalf("entry %q not found in %+v", name, entries)
	return dirEntry{}
}

// readVolumeID returns the PVD Volume Identifier (ECMA-119 §8.4.7) at offset
// 40, 32 bytes a-characters padded with spaces. Trailing spaces are stripped.
func readVolumeID(iso []byte) string {
	const sectorSize = 2048
	pvd := iso[16*sectorSize : 17*sectorSize]
	return strings.TrimRight(string(pvd[40:72]), " ")
}

// allPrimaryFiles walks the primary directory tree and returns every file
// keyed by slash-joined path (with leading "/"). Names are stripped of the
// ";1" version suffix so paths match the AddFile inputs.
func allPrimaryFiles(t *testing.T, iso []byte) map[string][]byte {
	t.Helper()
	const sectorSize = 2048
	pvd := iso[16*sectorSize : 17*sectorSize]
	rootRec := pvd[156:190]
	rootLBA := binary.LittleEndian.Uint32(rootRec[2:6])
	require.NotZero(t, rootLBA, "primary root LBA must be non-zero")

	out := make(map[string][]byte)
	walkPrimary(t, iso, rootLBA, "", out)
	return out
}

// walkPrimary recursively traverses the primary tree starting at the
// directory extent at lba (assumed sectorSize bytes), filling out with
// (path → bytes) for every file.
func walkPrimary(t *testing.T, iso []byte, lba uint32, prefix string, out map[string][]byte) {
	t.Helper()
	const sectorSize = 2048
	extent := iso[lba*sectorSize : (lba+1)*sectorSize]
	for _, e := range parseDirRecords(t, extent, true) {
		path := prefix + "/" + e.name
		if e.isDir {
			walkPrimary(t, iso, e.lba, path, out)
		} else {
			out[path] = iso[e.lba*sectorSize : e.lba*sectorSize+e.dataSize]
		}
	}
}

// TestZeroByteFile verifies that a zero-length file records dataSize=0 and
// occupies no sectors (LBA delta = 0 between empty and the following file),
// matching genisoimage 1.1.11 behaviour.
func TestZeroByteFile(t *testing.T) {
	fixed := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	w := &cloudiso.Writer{VolumeID: "cidata", CreationTime: fixed}
	require.NoError(t, w.AddDir("/", fixed))
	require.NoError(t, w.AddFile("empty", []byte{}, fixed))
	require.NoError(t, w.AddFile("nonempty", []byte("x"), fixed))

	var buf bytes.Buffer
	require.NoError(t, w.Write(&buf))
	iso := buf.Bytes()
	require.Equal(t, 0, len(iso)%2048, "image size must be multiple of 2048")

	// Round-trip via direct primary-tree walk — zero-byte file visible, no content.
	found := allPrimaryFiles(t, iso)
	got, ok := found["/empty"]
	require.True(t, ok, "empty file not present in tree")
	assert.Equal(t, 0, len(got), "empty file content must be zero bytes")

	// Direct PVD parse — verify dataSize=0 and zero-sector span (empty file
	// shares its LBA with the next file; no sectors are allocated).
	entries := parsePrimaryRootEntries(t, iso)
	emptyE := findEntry(t, entries, "empty")
	nonemptyE := findEntry(t, entries, "nonempty")
	assert.Equal(t, uint32(0), emptyE.dataSize, "empty file dataSize must be 0")
	assert.Equal(t, uint32(0), nonemptyE.lba-emptyE.lba,
		"empty file must occupy zero sectors (LBA delta = 0)")
}

// TestSectorBoundary verifies that file extent spans round up to whole
// sectors and that dataSize equals the declared length, not the rounded size.
// LBA deltas pin the (len + 2047) / 2048 formula — a buggy implementation
// that always reserves one extra sector would pass the dataSize check but
// fail the delta assertions.
func TestSectorBoundary(t *testing.T) {
	fixed := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	w := &cloudiso.Writer{VolumeID: "cidata", CreationTime: fixed}
	require.NoError(t, w.AddDir("/", fixed))
	a := bytes.Repeat([]byte{'a'}, 2048)
	b := bytes.Repeat([]byte{'b'}, 2049)
	c := bytes.Repeat([]byte{'c'}, 4096)
	require.NoError(t, w.AddFile("a2048", a, fixed))
	require.NoError(t, w.AddFile("b2049", b, fixed))
	require.NoError(t, w.AddFile("c4096", c, fixed))

	var buf bytes.Buffer
	require.NoError(t, w.Write(&buf))
	iso := buf.Bytes()
	require.Equal(t, 0, len(iso)%2048, "image size must be multiple of 2048")

	entries := parsePrimaryRootEntries(t, iso)
	aE := findEntry(t, entries, "a2048")
	bE := findEntry(t, entries, "b2049")
	cE := findEntry(t, entries, "c4096")

	assert.Equal(t, uint32(2048), aE.dataSize)
	assert.Equal(t, uint32(2049), bE.dataSize)
	assert.Equal(t, uint32(4096), cE.dataSize)

	assert.Equal(t, uint32(1), bE.lba-aE.lba, "a2048 occupies 1 sector")
	assert.Equal(t, uint32(2), cE.lba-bE.lba, "b2049 occupies 2 sectors")

	// c4096 occupies 2 sectors → its extent ends at cE.lba + 2.
	// The image total sector count must equal cE.lba + 2.
	totalSectors := uint32(len(iso) / 2048)
	assert.Equal(t, cE.lba+2, totalSectors, "c4096 occupies exactly 2 sectors")

	// Direct primary-tree walk — content must be byte-identical to input.
	found := allPrimaryFiles(t, iso)
	assert.True(t, bytes.Equal(a, found["/a2048"]))
	assert.True(t, bytes.Equal(b, found["/b2049"]))
	assert.True(t, bytes.Equal(c, found["/c4096"]))
}

// TestDuplicatePaths verifies that re-adding the same path, adding a file
// where a directory already exists, or adding a file inside a path component
// that is already a file, all return errors.
func TestDuplicatePaths(t *testing.T) {
	fixed := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)

	t.Run("file_over_file", func(t *testing.T) {
		w := &cloudiso.Writer{VolumeID: "TEST"}
		require.NoError(t, w.AddDir("/", fixed))
		require.NoError(t, w.AddFile("meta-data", []byte("first"), fixed))
		err := w.AddFile("meta-data", []byte("second"), fixed)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "meta-data")
	})

	// "a" was registered as a directory; AddFile("a") must error because
	// inserting a file with the same name as an existing directory is a conflict.
	t.Run("file_over_existing_dir", func(t *testing.T) {
		w := &cloudiso.Writer{VolumeID: "TEST"}
		require.NoError(t, w.AddDir("/", fixed))
		require.NoError(t, w.AddDir("a", fixed))
		require.NoError(t, w.AddFile("a/b", []byte("x"), fixed))
		err := w.AddFile("a", []byte("y"), fixed)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "a")
	})

	// "a" was registered as a file; AddFile("a/b") requires "a" to be a
	// directory, which it is not — must error.
	t.Run("dir_component_over_existing_file", func(t *testing.T) {
		w := &cloudiso.Writer{VolumeID: "TEST"}
		require.NoError(t, w.AddDir("/", fixed))
		require.NoError(t, w.AddFile("a", []byte("x"), fixed))
		err := w.AddFile("a/b", []byte("y"), fixed)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "a")
	})
}

// TestPathNormalization drives every path-edge case through AddFile and
// asserts that splitPath/validate reject them with errors carrying both a
// layer-specific substring and the offending path (from AddFile's wrapper).
func TestPathNormalization(t *testing.T) {
	fixed := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)

	// splitPath rejections.
	splitCases := []struct {
		path    string
		needles []string // layer-specific substrings (any one match is enough)
	}{
		{"", []string{"empty path"}},
		{"/", []string{"empty path"}},
		{"//", []string{"empty component", "double slash"}},
		{"foo//bar", []string{"empty component", "double slash"}},
		{"foo/", []string{"empty component", "double slash"}},
	}
	for _, tc := range splitCases {
		t.Run("split_"+tc.path, func(t *testing.T) {
			w := &cloudiso.Writer{VolumeID: "TEST"}
			require.NoError(t, w.AddDir("/", fixed))
			err := w.AddFile(tc.path, []byte("x"), fixed)
			require.Error(t, err)
			assertErrorContainsAny(t, err, tc.needles)
			// AddFile wraps with %q — path appears quoted.
			assert.Contains(t, err.Error(), tc.path)
		})
	}

	// validate rejections (after splitPath returns a component).
	validateCases := []struct {
		path      string
		offending string // the substring that AddFile %q quotes
	}{
		{".", "."},
		{"..", ".."},
		{"foo/.", "foo/."},
	}
	for _, tc := range validateCases {
		t.Run("validate_"+tc.path, func(t *testing.T) {
			w := &cloudiso.Writer{VolumeID: "TEST"}
			require.NoError(t, w.AddDir("/", fixed))
			err := w.AddFile(tc.path, []byte("x"), fixed)
			require.Error(t, err)
			assert.ErrorContains(t, err, "reserved name")
			assert.Contains(t, err.Error(), tc.offending)
		})
	}

	// Accepted: vanilla and leading slash both place the file at /meta-data.
	// Note: "/" is the root path for AddDir, but for AddFile it means "empty
	// path" — splitPath strips the leading slash and rejects the empty result.
	// Only "meta-data" (without leading slash) should be accepted here.
	for _, p := range []string{"meta-data", "/meta-data"} {
		t.Run("accept_"+p, func(t *testing.T) {
			w := &cloudiso.Writer{VolumeID: "cidata"}
			require.NoError(t, w.AddDir("/", fixed))
			require.NoError(t, w.AddFile(p, []byte("id"), fixed))
			var buf bytes.Buffer
			require.NoError(t, w.Write(&buf))
			found := allPrimaryFiles(t, buf.Bytes())
			_, ok := found["/meta-data"]
			assert.True(t, ok, "file must land at /meta-data")
		})
	}
}

// assertErrorContainsAny passes if err's message contains at least one needle.
func assertErrorContainsAny(t *testing.T, err error, needles []string) {
	t.Helper()
	msg := err.Error()
	for _, n := range needles {
		if strings.Contains(msg, n) {
			return
		}
	}
	t.Errorf("error %q does not contain any of %v", msg, needles)
}

// TestDeterminism builds two independent Writers with identical inputs and
// asserts that their byte output is identical. Two separate Writers (rather
// than one Writer's output compared with itself) diversify map iteration
// seeds, pointer addresses, and struct-field initialization order — catching
// accidental map-ordering or pointer-identity dependencies.
func TestDeterminism(t *testing.T) {
	fixed := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)

	build := func() []byte {
		w := &cloudiso.Writer{
			VolumeID:     "cidata",
			Publisher:    "cloudiso",
			CreationTime: fixed,
		}
		require.NoError(t, w.AddDir("/", fixed))
		require.NoError(t, w.AddFile("meta-data", []byte("id"), fixed))
		require.NoError(t, w.AddFile("user-data", []byte("ud"), fixed))
		require.NoError(t, w.AddFile("network-config", []byte("nc"), fixed))
		var buf bytes.Buffer
		require.NoError(t, w.Write(&buf))
		return buf.Bytes()
	}

	a := build()
	b := build()
	assert.True(t, bytes.Equal(a, b),
		"Write output differs across runs: len(a)=%d len(b)=%d", len(a), len(b))
}

// TestJolietFullRoundTrip walks the entire Joliet directory tree by parsing
// raw dir records (kiso uses the primary tree, so we cannot re-use it for
// Joliet validation), decodes UCS-2BE identifiers, and asserts that every
// input path reaches the Joliet tree with byte-identical content.
func TestJolietFullRoundTrip(t *testing.T) {
	fixed := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	w := &cloudiso.Writer{
		VolumeID:     "cidata",
		Publisher:    "cloudiso",
		CreationTime: fixed,
	}
	require.NoError(t, w.AddDir("/", fixed))
	require.NoError(t, w.AddDir("openstack", fixed))
	require.NoError(t, w.AddDir("openstack/latest", fixed))
	require.NoError(t, w.AddDir("ec2", fixed))
	require.NoError(t, w.AddDir("ec2/latest", fixed))

	want := map[string][]byte{
		"/meta-data":                       []byte("id"),
		"/user-data":                       []byte("ud"),
		"/openstack/latest/meta_data.json": []byte(`{}`),
		"/openstack/latest/user_data":      []byte("ud2"),
		"/ec2/latest/meta-data.json":       []byte(`{"e":1}`),
	}
	for p, c := range want {
		require.NoError(t, w.AddFile(strings.TrimPrefix(p, "/"), c, fixed))
	}

	var buf bytes.Buffer
	require.NoError(t, w.Write(&buf))
	iso := buf.Bytes()

	const sectorSize = 2048
	svd := iso[17*sectorSize : 18*sectorSize]

	// --- SVD header sanity (kept from the original TestJolietSVD) ---
	require.Equal(t, byte(2), svd[0], "SVD type")
	require.Equal(t, "CD001", string(svd[1:6]), "SVD std id")
	require.Equal(t, byte(1), svd[6], "SVD version")
	esc := svd[88:91]
	require.Equal(t, []byte{0x25, 0x2F, 0x45}, esc, "Joliet UCS-2 Level 3 escape sequence")

	// Volume Identifier at offset 40, 32 bytes — UCS-2BE "cidata" padded with 0x00 0x20.
	volID := svd[40:72]
	wantVolID := []byte{
		0x00, 'c', 0x00, 'i', 0x00, 'd', 0x00, 'a', 0x00, 't', 0x00, 'a',
		0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20,
		0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20,
	}
	require.Equal(t, wantVolID, volID, "SVD volume identifier UCS-2BE 'cidata'")

	// --- Walk the Joliet tree from the SVD root ---
	rootRec := svd[156:190]
	rootLBA := binary.LittleEndian.Uint32(rootRec[2:6])
	require.NotZero(t, rootLBA, "Joliet root LBA")

	got := make(map[string][]byte)
	walkJoliet(t, iso, rootLBA, "", got)

	// Every input file must appear at its Joliet path with identical bytes.
	require.Equal(t, want, got, "Joliet round-trip must reproduce inputs exactly")
}

// TestJolietSortByUCS2BE pins that Joliet child ordering is based on UCS-2BE
// bytewise compare of the identifier, not on primary sort keys.
func TestJolietSortByUCS2BE(t *testing.T) {
	fixed := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	w := &cloudiso.Writer{
		VolumeID:     "cidata",
		Publisher:    "cloudiso",
		CreationTime: fixed,
	}
	require.NoError(t, w.AddDir("/", fixed))
	require.NoError(t, w.AddFile(".a", []byte("dot"), fixed))
	require.NoError(t, w.AddFile("-a", []byte("dash"), fixed))
	require.NoError(t, w.AddFile("_a", []byte("underscore"), fixed))
	require.NoError(t, w.AddFile("A", []byte("upper"), fixed))
	require.NoError(t, w.AddFile("a", []byte("lower"), fixed))

	var buf bytes.Buffer
	require.NoError(t, w.Write(&buf))
	iso := buf.Bytes()

	got := parseJolietRootNames(t, iso)
	require.Equal(t, []string{"-a", ".a", "A", "_a", "a"}, got)
}

// walkJoliet recursively iterates the Joliet directory tree. For each file
// node, it stores (slash-path → bytes) into out. Directories add to the path
// prefix and recurse. Joliet does not strip the version suffix per
// dirrec.go:jolietFileID, so paths stay clean.
func walkJoliet(t *testing.T, iso []byte, dirLBA uint32, prefix string, out map[string][]byte) {
	t.Helper()
	const sectorSize = 2048
	extent := iso[dirLBA*sectorSize : (dirLBA+1)*sectorSize]

	off := 0
	idx := 0
	for off < len(extent) {
		lenDR := int(extent[off])
		if lenDR == 0 {
			break
		}
		// Skip dot (idx=0) and dotdot (idx=1).
		if idx < 2 {
			idx++
			off += lenDR
			continue
		}
		idx++
		rec := extent[off : off+lenDR]
		flags := rec[25]
		lenFI := int(rec[32])
		ident := rec[33 : 33+lenFI]
		name := decodeUCS2BE(t, ident)

		path := prefix + "/" + name
		lba := binary.LittleEndian.Uint32(rec[2:6])
		size := binary.LittleEndian.Uint32(rec[10:14])

		if flags&0x02 != 0 {
			walkJoliet(t, iso, lba, path, out)
		} else {
			out[path] = iso[lba*sectorSize : lba*sectorSize+size]
		}
		off += lenDR
	}
}

// decodeUCS2BE decodes a UCS-2BE byte sequence into a Go string. Surrogate
// pairs are rejected — Joliet validation forbids them, so any surrogate seen
// here is a writer bug.
func decodeUCS2BE(t *testing.T, b []byte) string {
	t.Helper()
	require.Equal(t, 0, len(b)%2, "UCS-2BE byte count must be even")
	var sb strings.Builder
	for i := 0; i < len(b); i += 2 {
		r := rune(b[i])<<8 | rune(b[i+1])
		if r >= 0xD800 && r <= 0xDFFF {
			t.Fatalf("UCS-2BE decode: surrogate code point U+%04X is invalid for Joliet", r)
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// parseJolietRootNames returns root child names from the Joliet tree in
// on-disk order (skipping dot and dotdot).
func parseJolietRootNames(t *testing.T, iso []byte) []string {
	t.Helper()
	const sectorSize = 2048
	svd := iso[17*sectorSize : 18*sectorSize]
	rootRec := svd[156:190]
	rootLBA := binary.LittleEndian.Uint32(rootRec[2:6])
	rootSize := binary.LittleEndian.Uint32(rootRec[10:14])
	require.NotZero(t, rootLBA, "Joliet root LBA")
	require.Greater(t, rootSize, uint32(0), "Joliet root size")

	extent := iso[rootLBA*sectorSize : rootLBA*sectorSize+rootSize]
	var out []string
	off := 0
	idx := 0
	for off < len(extent) {
		lenDR := int(extent[off])
		if lenDR == 0 {
			off = ((off / sectorSize) + 1) * sectorSize
			continue
		}
		if off+lenDR > len(extent) {
			t.Fatalf("Joliet dir record overruns extent: off=%d lenDR=%d size=%d", off, lenDR, len(extent))
		}
		rec := extent[off : off+lenDR]
		if idx < 2 {
			idx++
			off += lenDR
			continue
		}
		lenFI := int(rec[32])
		ident := rec[33 : 33+lenFI]
		out = append(out, decodeUCS2BE(t, ident))
		off += lenDR
	}
	return out
}
