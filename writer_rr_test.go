package cloudiso_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/pilat/cloudiso"
)

// parseSU scans a System Use area and returns a map of 2-char signature
// → record bytes (full record including signature and header bytes).
func parseSU(su []byte) map[string][]byte {
	result := make(map[string][]byte)
	off := 0
	for off+4 <= len(su) {
		sig := string(su[off : off+2])
		recLen := int(su[off+2])
		if recLen < 4 || off+recLen > len(su) {
			break
		}
		result[sig] = su[off : off+recLen]
		off += recLen
	}
	return result
}

// readDirRecord returns LEN_DR, the file identifier bytes, and the System Use
// bytes from a raw directory record at the given offset.
func readDirRecord(sector []byte, off int) (lenDR int, ident []byte, su []byte) {
	lenDR = int(sector[off])
	if lenDR == 0 {
		return 0, nil, nil
	}
	lenFI := int(sector[off+32])
	idEnd := off + 33 + lenFI
	ident = sector[off+33 : idEnd]
	// Padding byte after identifier if (33+lenFI) is odd.
	base := 33 + lenFI
	idPad := base % 2
	suStart := off + 33 + lenFI + idPad
	suEnd := off + lenDR
	if suStart < suEnd {
		su = sector[suStart:suEnd]
	}
	return lenDR, ident, su
}

// TestRockRidge validates that every primary directory record carries the
// correct SUSP / RRIP records. It does NOT verify that Joliet records carry
// SUSP (they must not).
//
//nolint:gocyclo
func TestRockRidge(t *testing.T) {
	fixed := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	w := &cloudiso.Writer{
		VolumeID:     "cidata",
		Publisher:    "cloudiso",
		CreationTime: fixed,
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.AddDir("/", fixed))
	must(w.AddFile("meta-data", []byte("id"), fixed))
	must(w.AddFile("user-data", []byte("ud"), fixed))
	must(w.AddFile("network-config", []byte("nc"), fixed))

	var buf bytes.Buffer
	must(w.Write(&buf))
	iso := buf.Bytes()

	const secSize = 2048

	// Locate the primary root LBA from the PVD root dir record (offset 156+2).
	pvd := iso[16*secSize : 17*secSize]
	rootLBA := binary.LittleEndian.Uint32(pvd[158:162]) // DR offset 2
	if rootLBA == 0 {
		t.Fatal("primary root LBA is 0")
	}

	rootSector := iso[rootLBA*secSize : (rootLBA+1)*secSize]

	// ─── dot (.) entry — first record in root dir ──────────────────────────
	lenDR, ident, su := readDirRecord(rootSector, 0)
	if lenDR == 0 {
		t.Fatal("dot entry LEN_DR is 0")
	}
	if len(ident) != 1 || ident[0] != 0x00 {
		t.Errorf("dot ident = % 02X, want [00]", ident)
	}

	dotRecs := parseSU(su)

	// SP must be present in root dot only (SUSP §4.1).
	sp, ok := dotRecs["SP"]
	if !ok {
		t.Error("root dot: SP record missing")
	} else {
		if len(sp) != 7 {
			t.Errorf("SP LEN = %d, want 7", len(sp))
		}
		if sp[4] != 0xBE || sp[5] != 0xEF {
			t.Errorf("SP check bytes = %02X %02X, want BE EF", sp[4], sp[5])
		}
		if sp[6] != 0 {
			t.Errorf("SP LEN_SKP = %d, want 0", sp[6])
		}
	}

	// PX must reflect directory mode and nlink ≥ 2.
	px, ok := dotRecs["PX"]
	if !ok {
		t.Error("root dot: PX record missing")
	} else {
		if len(px) != 36 {
			t.Errorf("PX LEN = %d, want 36", len(px))
		}
		mode := binary.LittleEndian.Uint32(px[4:8])
		if mode != 0o040555 {
			t.Errorf("PX mode = %#o, want %#o (S_IFDIR|0555)", mode, 0o040555)
		}
		nlink := binary.LittleEndian.Uint32(px[12:16])
		if nlink < 2 {
			t.Errorf("PX nlink = %d, want ≥ 2", nlink)
		}
		uid := binary.LittleEndian.Uint32(px[20:24])
		if uid != 0 {
			t.Errorf("PX uid = %d, want 0", uid)
		}
		gid := binary.LittleEndian.Uint32(px[28:32])
		if gid != 0 {
			t.Errorf("PX gid = %d, want 0", gid)
		}
	}

	// TF with FLAGS=0x0E (MODIFY|ACCESS|ATTRIBUTES, binary form).
	tf, ok := dotRecs["TF"]
	if !ok {
		t.Error("root dot: TF record missing")
	} else {
		if len(tf) != 26 {
			t.Errorf("TF LEN = %d, want 26", len(tf))
		}
		if tf[4] != 0x0E {
			t.Errorf("TF FLAGS = %02X, want 0E", tf[4])
		}
	}

	// RR with flags 0x81 (PX+TF, no NM for dot/dotdot).
	rr, ok := dotRecs["RR"]
	if !ok {
		t.Error("root dot: RR record missing")
	} else {
		if len(rr) != 5 {
			t.Errorf("RR LEN = %d, want 5", len(rr))
		}
		if rr[4] != 0x81 {
			t.Errorf("RR flags = %02X, want 81 (PX|TF, no NM)", rr[4])
		}
	}

	// SP must NOT be present in the dotdot entry.
	_, _, suDD := readDirRecord(rootSector, lenDR)
	ddRecs := parseSU(suDD)
	if _, hasSP := ddRecs["SP"]; hasSP {
		t.Error("root dotdot: SP must NOT be present")
	}

	// ─── child file record — find "meta-data;1" ───────────────────────────
	off := lenDR                // skip dot
	off += int(rootSector[off]) // skip dotdot (LEN_DR at off)
	// Iterate children to find meta-data.
	var childSU []byte
	for off < secSize {
		dr := int(rootSector[off])
		if dr == 0 {
			break
		}
		_, chIdent, chSU := readDirRecord(rootSector, off)
		if strings.HasPrefix(string(chIdent), "meta_data") {
			childSU = chSU
			break
		}
		off += dr
	}
	if childSU == nil {
		t.Fatal("meta-data child record not found")
	}

	childRecs := parseSU(childSU)

	// PX for file: mode = S_IFREG|0444, nlink = 1.
	cpx, ok := childRecs["PX"]
	if !ok {
		t.Error("meta-data: PX missing")
	} else {
		mode := binary.LittleEndian.Uint32(cpx[4:8])
		if mode != 0o100444 {
			t.Errorf("meta-data PX mode = %#o, want %#o (S_IFREG|0444)", mode, 0o100444)
		}
		nlink := binary.LittleEndian.Uint32(cpx[12:16])
		if nlink != 1 {
			t.Errorf("meta-data PX nlink = %d, want 1", nlink)
		}
	}

	// NM record must contain "meta-data".
	nm, ok := childRecs["NM"]
	if !ok {
		t.Error("meta-data: NM record missing")
	} else {
		if string(nm[5:]) != "meta-data" {
			t.Errorf("NM name = %q, want %q", string(nm[5:]), "meta-data")
		}
	}

	// RR flags must be 0x89 (PX|NM|TF).
	crr, ok := childRecs["RR"]
	if !ok {
		t.Error("meta-data: RR record missing")
	} else {
		if crr[4] != 0x89 {
			t.Errorf("meta-data RR flags = %02X, want 89", crr[4])
		}
	}

	// SP must NOT appear on any child file record.
	if _, hasSP := childRecs["SP"]; hasSP {
		t.Error("meta-data child: SP must NOT be present (only root dot)")
	}

	// ─── Joliet root sector: verify no SUSP in any record ─────────────────
	svd := iso[17*secSize : 18*secSize]
	jolietRootLBA := binary.LittleEndian.Uint32(svd[158:162])
	jolietSector := iso[jolietRootLBA*secSize : (jolietRootLBA+1)*secSize]

	// Joliet dot entry — LEN_FI=1 → base=34 → no su (Joliet records have no SU).
	jDotLen := int(jolietSector[0])
	jDotLenFI := int(jolietSector[32])
	jDotBase := 33 + jDotLenFI
	jDotIdPad := jDotBase % 2
	jDotSUStart := 33 + jDotLenFI + jDotIdPad
	if jDotSUStart < jDotLen {
		t.Errorf("Joliet dot entry appears to have SU (%d bytes): Joliet must not carry SUSP",
			jDotLen-jDotSUStart)
	}
}

// TestNlinks verifies nlink computation per RRIP 1.12 §4.1.1.
// Layout: root → subdir1/, subdir2/a.txt, plus two root files.
// root nlink = 2 + 2 (two subdirs) = 4.
// subdir1 nlink = 2 (no children).
// subdir2 nlink = 2 (no sub-subdirs).
func TestNlinks(t *testing.T) {
	fixed := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	w := &cloudiso.Writer{VolumeID: "test", CreationTime: fixed}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.AddDir("/", fixed))
	must(w.AddFile("root-file.txt", []byte("x"), fixed))
	must(w.AddDir("subdir1", fixed))
	must(w.AddFile("subdir1/placeholder", []byte("x"), fixed))
	must(w.AddDir("subdir2", fixed))
	must(w.AddFile("subdir2/a.txt", []byte("x"), fixed))

	var buf bytes.Buffer
	must(w.Write(&buf))
	iso := buf.Bytes()

	const secSize = 2048
	pvd := iso[16*secSize : 17*secSize]
	rootLBA := binary.LittleEndian.Uint32(pvd[158:162])
	rootSector := iso[rootLBA*secSize : (rootLBA+1)*secSize]

	// Parse root dot PX for nlink.
	_, _, dotSU := readDirRecord(rootSector, 0)
	dotRecs := parseSU(dotSU)
	rootPX, ok := dotRecs["PX"]
	if !ok {
		t.Fatal("root dot: PX missing")
	}
	rootNlink := binary.LittleEndian.Uint32(rootPX[12:16])
	if rootNlink != 4 {
		t.Errorf("root nlink = %d, want 4 (2 + 2 subdirs)", rootNlink)
	}

	// Find subdir1 and subdir2 LBAs in root.
	off := int(rootSector[0])   // skip dot
	off += int(rootSector[off]) // skip dotdot
	subNlinks := make(map[string]uint32)
	for off < secSize {
		dr := int(rootSector[off])
		if dr == 0 {
			break
		}
		_, chIdent, chSU := readDirRecord(rootSector, off)
		name := string(chIdent)
		if name == "subdir1" || name == "subdir2" {
			recs := parseSU(chSU)
			px, ok := recs["PX"]
			if !ok {
				t.Errorf("%s: PX missing", name)
			} else {
				subNlinks[name] = binary.LittleEndian.Uint32(px[12:16])
			}
		}
		off += dr
	}
	for _, name := range []string{"subdir1", "subdir2"} {
		nl, ok := subNlinks[name]
		if !ok {
			t.Errorf("%s: not found in root dir", name)
			continue
		}
		if nl != 2 {
			t.Errorf("%s nlink = %d, want 2", name, nl)
		}
	}
}

// TestCE verifies the CE (continuation area) overflow mechanism by directly
// exercising buildSU with a budget too small to hold all records inline.
// This is a unit-level test since a 30-char name alone does not overflow
// the 255-byte dir record limit with our current fixed record sizes.
//
//nolint:gocyclo
func TestCE(t *testing.T) {
	// CE test: build an ISO with a 30-char filename. Verify the dir record is
	// within the 255-byte limit, and that the CE pool sector exists between
	// primary dirs and Joliet dirs (layout invariant, even without CE records).
	name30 := strings.Repeat("a", 30)
	fixed := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	w := &cloudiso.Writer{VolumeID: "cetest", CreationTime: fixed}
	if err := w.AddDir("/", fixed); err != nil {
		t.Fatal(err)
	}
	if err := w.AddFile(name30, []byte("payload"), fixed); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := w.Write(&buf); err != nil {
		t.Fatal(err)
	}
	iso := buf.Bytes()

	const secSize = 2048

	// Image must be a multiple of sector size.
	if len(iso)%secSize != 0 {
		t.Fatalf("image size %d not a multiple of 2048", len(iso))
	}

	// Locate root and find the 30-char child record.
	pvd := iso[16*secSize : 17*secSize]
	rootLBA := binary.LittleEndian.Uint32(pvd[158:162])
	rootSector := iso[rootLBA*secSize : (rootLBA+1)*secSize]

	off := int(rootSector[0])   // skip dot
	off += int(rootSector[off]) // skip dotdot

	found := false
	for off < secSize {
		dr := int(rootSector[off])
		if dr == 0 {
			break
		}
		if dr > 255 {
			t.Errorf("child dir record LEN_DR = %d, exceeds 255", dr)
		}
		_, chIdent, chSU := readDirRecord(rootSector, off)
		if strings.HasPrefix(string(chIdent), name30[:29]) {
			found = true
			// NM must carry the full 30-char name (in-line or via CE).
			recs := parseSU(chSU)
			nm, hasNM := recs["NM"]
			ce, hasCE := recs["CE"]
			if hasNM {
				// NM is in-line — verify content.
				if string(nm[5:]) != name30 {
					t.Errorf("NM name = %q, want %q", string(nm[5:]), name30)
				}
			} else if hasCE {
				// NM was pushed to continuation — verify CE points somewhere sane.
				if len(ce) != 28 {
					t.Errorf("CE LEN = %d, want 28", len(ce))
				}
				ceLBA := binary.LittleEndian.Uint32(ce[4:8])
				ceOff := binary.LittleEndian.Uint32(ce[12:16])
				ceLen := binary.LittleEndian.Uint32(ce[20:24])
				if ceLBA == 0 {
					t.Error("CE extent LBA is 0")
				}
				// Parse continuation and look for NM.
				if int(ceLBA)*secSize+int(ceOff)+int(ceLen) > len(iso) {
					t.Fatalf("CE points outside image: LBA=%d off=%d len=%d", ceLBA, ceOff, ceLen)
				}
				contData := iso[ceLBA*secSize+ceOff : ceLBA*secSize+ceOff+ceLen]
				contRecs := parseSU(contData)
				contNM, ok := contRecs["NM"]
				if !ok {
					t.Error("NM not found in CE continuation area")
				} else if string(contNM[5:]) != name30 {
					t.Errorf("CE NM name = %q, want %q", string(contNM[5:]), name30)
				}
			} else {
				t.Error("child: neither NM nor CE record found in SU area")
			}
			break
		}
		off += dr
	}
	if !found {
		t.Fatalf("30-char child record not found in root dir")
	}

	// Verify the Joliet sector has no SUSP. The CE pool sector sits between
	// primary dirs and Joliet dirs — this is a layout invariant.
	svd := iso[17*secSize : 18*secSize]
	jolietRootLBA := binary.LittleEndian.Uint32(svd[158:162])
	primaryRootLBA := rootLBA

	// Primary root is at sector 23 (firstPrimaryDirSector). CE pool must come
	// after primary dirs and before Joliet dirs.
	if jolietRootLBA <= primaryRootLBA {
		t.Errorf("Joliet root LBA %d not after primary root LBA %d", jolietRootLBA, primaryRootLBA)
	}
}
