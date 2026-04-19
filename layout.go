package cloudiso

import (
	"fmt"
	"io"
	"sort"
	"time"
)

// effectiveMaxDirRecordLen caps the declared LEN_DR of a directory record.
// ECMA-119 §9.1 allows up to 255; we cap at 254 (even) so suAvailable always
// returns an even number and the `byte(totalLen)` cast in encodeDirRecord
// can never wrap to 0 on a 256-byte record. Tests in this package override
// it to force CE overflow paths that are unreachable via the permissive name
// validation in names.go (30-char component cap + fixed RRIP record set).
// Production code never writes to this variable.
var effectiveMaxDirRecordLen = maxDirRecordLen

// layout holds the computed image layout after pass 1.
type layout struct {
	root *node

	// dirs holds directories in DFS reverse-insertion-order —
	// the order genisoimage's assign_directory_addresses assigns LBAs.
	// This is the order used for dir extent emission in pass 2.
	dirs []*node

	// ptDirs holds directories in BFS alphabetical order — the order
	// required for ECMA-119 path table records (parent before child,
	// alphabetical within each level).
	ptDirs []*node

	files []*node // AddFile order

	ptLEbytes       []byte // primary path table (LE) — length == primaryPtBlocks*sectorSize
	ptMEbytes       []byte // primary path table (ME)
	jolietPtLEbytes []byte // Joliet path table (LE)
	jolietPtMEbytes []byte // Joliet path table (ME)

	// Path table LBAs and block counts (blocks = sectors, rounded up to even
	// per genisoimage 1.1.11 convention).
	primaryPtLLBA   uint32
	primaryPtMLBA   uint32
	jolietPtLLBA    uint32
	jolietPtMLBA    uint32
	primaryPtBlocks uint32
	jolietPtBlocks  uint32

	// True PT byte counts (not padded) — the value written into PVD/SVD
	// `path_table_size` fields.
	primaryPtBytes uint32
	jolietPtBytes  uint32

	totalSectors uint32
	ce           *ceAlloc
}

// computeLayout is pass 1: walks the tree, assigns LBAs to every dir and
// file extent, and computes path tables. Layout order (matches genisoimage
// 1.1.11):
//
//	sectors 0..15  system area (zeros)
//	sector  16     PVD
//	sector  17     SVD (Joliet)
//	sector  18     VDST
//	sector  19     version block (written as zeros — mkisofs placeholder)
//	sector  20     primary L-path table (padded to primaryPtBlocks sectors, rounded up to even)
//	...            primary M-path table (same size as L)
//	...            Joliet L-path table (padded to jolietPtBlocks sectors)
//	...            Joliet M-path table
//	...            primary directory extents (DFS reverse-insertion)
//	...            Joliet directory extents (DFS reverse-insertion)
//	...            CE pool (extension_desc in geniso ordering)
//	...            file data extents (shared, AddFile order)
//
//nolint:gocyclo
func computeLayout(root *node) (*layout, error) {
	// ptDirs: BFS alphabetical — required for ECMA-119 path table records.
	ptDirs := bfsOrder(root)

	// emitDirs: DFS reverse-insertion-order — matches genisoimage LBA assignment.
	emitDirs := dfsReverseInsertOrder(root)

	root.ptParent = nil
	for _, d := range ptDirs {
		for _, c := range d.children {
			if c.isDir {
				c.ptParent = d
			}
		}
	}

	computeNlinks(root)

	// Build path tables without LBAs yet — only sizes matter here. Actual LBAs
	// are patched in once directory LBAs are assigned.
	primaryLE, _ := encodePathTables(ptDirs)
	jolietLE, _ := encodeJolietPathTables(ptDirs)
	primaryPtBytes := uint32(len(primaryLE))
	jolietPtBytes := uint32(len(jolietLE))
	primaryPtBlocks := roundUpEvenBlocks(primaryPtBytes)
	jolietPtBlocks := roundUpEvenBlocks(jolietPtBytes)

	// Layout path tables.
	cursor := uint32(pathTableStart)
	primaryPtLLBA := cursor
	cursor += primaryPtBlocks
	primaryPtMLBA := cursor
	cursor += primaryPtBlocks
	jolietPtLLBA := cursor
	cursor += jolietPtBlocks
	jolietPtMLBA := cursor
	cursor += jolietPtBlocks

	// Compute primary dir extent sizes in sectors first so we can assign LBAs
	// based on per-directory span. SU doesn't reference LBAs, so we compute
	// SU first (with zero LBA placeholders) then refine after CE allocation.

	for _, d := range emitDirs {
		d.size = 0 // invalidated until pass below
	}

	// Reserve primary dir LBAs assuming one sector each; refined after SU is built.
	// Iterate in DFS reverse-insertion order — this is the order genisoimage assigns LBAs.
	dirLBAs := make([]uint32, len(emitDirs))
	dirSectors := make([]uint32, len(emitDirs))
	for i, d := range emitDirs {
		dirLBAs[i] = cursor
		dirSectors[i] = 1
		d.lba = dirLBAs[i]
		d.size = sectorSize
		cursor++
	}

	// Joliet dirs follow immediately after primary dirs — BEFORE the CE pool.
	// This matches genisoimage's output order:
	//   dirtree_desc → jdirtree_desc → extension_desc → files_desc
	// (genisoimage.c:3587-3599). Joliet dirs may span multiple sectors.
	jolietDirSectors := make([]uint32, len(emitDirs))
	for i, d := range emitDirs {
		jsize := computeJolietDirExtentSize(d)
		jsectors := (jsize + sectorSize - 1) / sectorSize
		if jsectors == 0 {
			jsectors = 1
		}
		jolietDirSectors[i] = jsectors
		d.jolietLBA = cursor
		d.jolietSize = jsectors * sectorSize
		cursor += jsectors
	}

	// CE pool sits after Joliet dirs.
	ceBase := cursor
	ce := newCEAlloc(ceBase)

	for _, d := range emitDirs {
		isRoot := (d.ptParent == nil)
		d.suAsDot = computeDotSU(d, isRoot, ce)
		d.suAsDotDot = computeDotDotSU(d, ce)
		for _, c := range d.children {
			c.suAsChild = computeChildSU(c, ce)
		}
	}

	// Now that SU is known, compute true sector span for every primary dir.
	// Records cannot straddle sector boundaries (ECMA-119 §6.8.1.1), so the
	// extent size must accommodate per-sector record packing plus padding.
	growth := int64(0)
	for i, d := range emitDirs {
		span := primaryDirSectors(d)
		if span > dirSectors[i] {
			growth += int64(span - dirSectors[i])
			dirSectors[i] = span
		}
		d.size = dirSectors[i] * sectorSize
	}
	if growth > 0 {
		// Recompute LBAs for all regions: primary dirs grew, so Joliet dirs and
		// CE pool must shift accordingly.
		cursor = uint32(pathTableStart) + 2*primaryPtBlocks + 2*jolietPtBlocks
		for i, d := range emitDirs {
			dirLBAs[i] = cursor
			d.lba = cursor
			cursor += dirSectors[i]
		}
		// Joliet dirs: recompute with updated sector counts.
		for i, d := range emitDirs {
			d.jolietLBA = cursor
			d.jolietSize = jolietDirSectors[i] * sectorSize
			cursor += jolietDirSectors[i]
		}
		ceBase = cursor
		// CE pool LBA changed — recreate the allocator and repopulate.
		ce = newCEAlloc(ceBase)
		for _, d := range emitDirs {
			isRoot := (d.ptParent == nil)
			d.suAsDot = computeDotSU(d, isRoot, ce)
			d.suAsDotDot = computeDotDotSU(d, ce)
			for _, c := range d.children {
				c.suAsChild = computeChildSU(c, ce)
			}
		}
	}

	// Advance cursor past CE pool to the file data region.
	cursor = ceBase + uint32(ce.sectorCount())

	var files []*node
	collectFiles(root, &files)
	for _, f := range files {
		f.lba = cursor
		sectors := (uint32(len(f.data)) + sectorSize - 1) / sectorSize
		f.size = uint32(len(f.data))
		cursor += sectors
	}

	// Rebuild path tables with real LBAs now that dir LBAs are final.
	// Use ptDirs (BFS alphabetical) for correct path table record ordering.
	primaryLE, primaryME := encodePathTables(ptDirs)
	jolietLE, jolietME := encodeJolietPathTables(ptDirs)

	// Pad each path table to primaryPtBlocks * sectorSize so the sector layout
	// is deterministic — genisoimage writes all allocated blocks even if the PT
	// is smaller.
	primaryLEPadded := padPathTable(primaryLE, primaryPtBlocks)
	primaryMEPadded := padPathTable(primaryME, primaryPtBlocks)
	jolietLEPadded := padPathTable(jolietLE, jolietPtBlocks)
	jolietMEPadded := padPathTable(jolietME, jolietPtBlocks)

	return &layout{
		root:            root,
		dirs:            emitDirs,
		ptDirs:          ptDirs,
		files:           files,
		ptLEbytes:       primaryLEPadded,
		ptMEbytes:       primaryMEPadded,
		jolietPtLEbytes: jolietLEPadded,
		jolietPtMEbytes: jolietMEPadded,
		primaryPtLLBA:   primaryPtLLBA,
		primaryPtMLBA:   primaryPtMLBA,
		jolietPtLLBA:    jolietPtLLBA,
		jolietPtMLBA:    jolietPtMLBA,
		primaryPtBlocks: primaryPtBlocks,
		jolietPtBlocks:  jolietPtBlocks,
		primaryPtBytes:  primaryPtBytes,
		jolietPtBytes:   jolietPtBytes,
		totalSectors:    cursor,
		ce:              ce,
	}, nil
}

// roundUpEvenBlocks returns the sector count for a path table, rounded up to
// the next even number. geniso 1.1.11 emits every path table as an even
// block count so that L and M pairs align on 2-sector boundaries
// (genisoimage.c:3490-3496).
func roundUpEvenBlocks(ptBytes uint32) uint32 {
	blocks := (ptBytes + sectorSize - 1) / sectorSize
	if blocks == 0 {
		blocks = 1
	}
	if blocks%2 != 0 {
		blocks++
	}
	return blocks
}

// padPathTable returns a copy of pt padded with zeros to exactly blocks*sectorSize bytes.
func padPathTable(pt []byte, blocks uint32) []byte {
	want := int(blocks) * sectorSize
	if len(pt) >= want {
		return pt[:want]
	}
	out := make([]byte, want)
	copy(out, pt)
	return out
}

// primaryDirSectors returns the number of sectors a primary directory extent
// must occupy given its full SU-including records. Records may not straddle
// sector boundaries (ECMA-119 §6.8.1.1) — when the next record wouldn't fit
// in the remaining bytes of the current sector, we pad and roll to the next
// sector.
func primaryDirSectors(d *node) uint32 {
	t := time.Time{}
	dot := encodeDirRecord([]byte{0x00}, 0, 0, 0x02, t, d.suAsDot)
	dotdot := encodeDirRecord([]byte{0x01}, 0, 0, 0x02, t, d.suAsDotDot)
	sectors := uint32(1)
	used := uint32(len(dot) + len(dotdot))
	if used > sectorSize {
		return 2 // shouldn't happen with current SU sizes; keep the bound defensive
	}

	for _, c := range d.children {
		var ident []byte
		if c.isDir {
			ident = []byte(c.name)
		} else {
			ident = []byte(fileID(c.name))
		}
		rec := encodeDirRecord(ident, 0, 0, 0, t, c.suAsChild)
		recLen := uint32(len(rec))
		if used > 0 && used+recLen >= sectorSize {
			// Roll to next sector. Require at least one padding byte after the
			// last record in each sector (the null terminator), matching
			// genisoimage's sector-packing behaviour (>= not >).
			sectors++
			used = 0
		}
		used += recLen
	}
	return sectors
}

// suAvailable returns the number of bytes available for System Use in a dir
// record with the given LEN_FI. ECMA-119 §9.1: total LEN_DR ≤ 255, and
// 33+LEN_FI+(LEN_FI%2==0 ? 1 : 0) bytes are fixed. The SU area fills
// the remainder up to effectiveMaxDirRecordLen.
func suAvailable(lenFI int) int {
	base := drFixedLen + lenFI
	idPad := base % 2
	return effectiveMaxDirRecordLen - (base + idPad)
}

// computeDotSU builds (and allocates CE for) the SU for a dot entry.
// isRoot=true → SP record is prepended (SUSP §4.1: only root dot) and the ER
// record announcing RRIP_1991A (SUSP §5.5) is appended into the CE pool.
// Uses d.mtime for all TF timestamps (MODIFY/ACCESS/ATTRIBUTES).
func computeDotSU(d *node, isRoot bool, ce *ceAlloc) []byte {
	// dot entry: LEN_FI = 1 (identifier 0x00)
	avail := suAvailable(1)
	// CE alloc placeholder: we need to pass ceExt/ceOff to buildSU,
	// but we don't know until we call alloc. Compute contSU length first
	// to know if CE is needed, then alloc.
	mainSU, contSU := buildSU(
		isRoot, false, isRoot, "",
		posixModeDir, d.nlink,
		d.mtime, d.mtime, avail, 0, 0, // ceExt/ceOff placeholders
	)
	if contSU != nil {
		// Allocate real CE slot and rebuild with correct address.
		lbaOut, offOut := ce.alloc(len(contSU))
		mainSU, contSU = buildSU(
			isRoot, false, isRoot, "",
			posixModeDir, d.nlink,
			d.mtime, d.mtime, avail, lbaOut, offOut,
		)
		ce.write(lbaOut, offOut, contSU)
	}
	return mainSU
}

// computeDotDotSU builds the SU for a dotdot entry.
// Uses the parent's mtime (or d.mtime for root, whose dotdot is self) for all
// TF timestamps (MODIFY/ACCESS/ATTRIBUTES).
func computeDotDotSU(d *node, ce *ceAlloc) []byte {
	// dotdot: LEN_FI = 1 (identifier 0x01)
	avail := suAvailable(1)
	// Parent nlink/mtime: for root dotdot the parent is self.
	var parentMode = posixModeDir
	var parentNlink uint32
	var parentMtime time.Time
	if d.ptParent == nil {
		parentNlink = d.nlink
		parentMtime = d.mtime
	} else {
		parentNlink = d.ptParent.nlink
		parentMtime = d.ptParent.mtime
	}
	mainSU, contSU := buildSU(
		false, false, false, "",
		parentMode, parentNlink,
		parentMtime, parentMtime, avail, 0, 0,
	)
	if contSU != nil {
		lbaOut, offOut := ce.alloc(len(contSU))
		mainSU, contSU = buildSU(
			false, false, false, "",
			parentMode, parentNlink,
			parentMtime, parentMtime, avail, lbaOut, offOut,
		)
		ce.write(lbaOut, offOut, contSU)
	}
	return mainSU
}

// computeChildSU builds (and allocates CE for) the SU for a child node record.
// Uses c.mtime for all TF timestamps (MODIFY/ACCESS/ATTRIBUTES).
func computeChildSU(c *node, ce *ceAlloc) []byte {
	var ident string
	var mode uint32
	if c.isDir {
		ident = translateISO9660(c.name)
		mode = posixModeDir
	} else {
		ident = fileID(c.name) // e.g. "meta_data.;1"
		mode = posixModeFile
	}
	lenFI := len(ident)
	avail := suAvailable(lenFI)
	mainSU, contSU := buildSU(
		false, true, false, c.name,
		mode, c.nlink,
		c.mtime, c.mtime, avail, 0, 0,
	)
	if contSU != nil {
		lbaOut, offOut := ce.alloc(len(contSU))
		mainSU, contSU = buildSU(
			false, true, false, c.name,
			mode, c.nlink,
			c.mtime, c.mtime, avail, lbaOut, offOut,
		)
		ce.write(lbaOut, offOut, contSU)
	}
	return mainSU
}

// computeJolietDirExtentSize returns the byte count for Joliet dir entries.
func computeJolietDirExtentSize(d *node) uint32 {
	size := uint32(dotLen + dotLen) // dot + dotdot: always 34 bytes each (1-byte id)
	for _, c := range d.children {
		size += uint32(jolietDirRecordLen(c))
	}
	return size
}

// jolietDirRecordLen returns the byte length of a Joliet directory record for c.
func jolietDirRecordLen(c *node) int {
	var id []byte
	if c.isDir {
		id = jolietDirID(c.name)
	} else {
		id = jolietFileID(c.name)
	}
	lenFI := len(id)
	base := drFixedLen + lenFI
	return base + (base % 2)
}

// collectFiles appends file nodes in DFS order matching genisoimage's file
// data extent assignment. The traversal order is:
//   - Append this directory's own file children first (alphabetical order).
//   - Then recurse into subdirectories in reverse insertion order (last
//     inserted first), matching dfsReverseInsertOrder.
func collectFiles(d *node, out *[]*node) {
	// Files in this directory come first (children sorted alphabetically).
	for _, c := range d.children {
		if !c.isDir {
			*out = append(*out, c)
		}
	}
	// Recurse into subdirs in reverse insertion order.
	dirs := make([]*node, 0, len(d.children))
	for _, c := range d.children {
		if c.isDir {
			dirs = append(dirs, c)
		}
	}
	sort.Slice(dirs, func(i, j int) bool {
		return dirs[i].insertionSeq > dirs[j].insertionSeq
	})
	for _, c := range dirs {
		collectFiles(c, out)
	}
}

// emit is pass 2: writes the complete ISO image to w.

//nolint:gocyclo
func emit(w io.Writer, l *layout, volumeID, publisher, preparer string, t time.Time) error {
	// System area: 16 zero sectors (0..15).
	if err := writeZeroSectors(w, systemAreaSectors); err != nil {
		return fmt.Errorf("system area: %w", err)
	}

	// PVD (sector 16): points at primary root.
	// The root dir record inside the PVD uses the root node's mtime; t is
	// only the PVD volume_creation_date (ECMA-119 §8.4.26.1).
	rootRec := encodeRootDirRecord(l.root.lba, l.root.size, l.root.mtime)
	pvd, err := encodePVD(
		volumeID,
		publisher,
		preparer,
		t,
		l.totalSectors,
		l.primaryPtLLBA,
		l.primaryPtMLBA,
		l.primaryPtBytes,
		rootRec,
	)
	if err != nil {
		return fmt.Errorf("PVD: %w", err)
	}
	if _, err := w.Write(pvd[:]); err != nil {
		return fmt.Errorf("write PVD: %w", err)
	}

	// SVD (sector 17): points at Joliet root.
	jolietRootRec := encodeRootDirRecord(l.root.jolietLBA, l.root.jolietSize, l.root.mtime)
	svd := encodeSVD(
		volumeID,
		publisher,
		preparer,
		t,
		l.totalSectors,
		l.jolietPtLLBA,
		l.jolietPtMLBA,
		l.jolietPtBytes,
		jolietRootRec,
	)
	if _, err := w.Write(svd[:]); err != nil {
		return fmt.Errorf("write SVD: %w", err)
	}

	// VDST (sector 18).
	vdst := encodeVDST()
	if _, err := w.Write(vdst[:]); err != nil {
		return fmt.Errorf("write VDST: %w", err)
	}

	// Version block placeholder (sector 19): one all-zero sector. genisoimage
	// writes "MKI " + timestamps here but our byte-match cases exercise
	// a path that produces an all-zero block.
	if err := writeZeroSectors(w, 1); err != nil {
		return fmt.Errorf("version block: %w", err)
	}

	// Primary path tables, each padded to primaryPtBlocks*sectorSize.
	if _, err := w.Write(l.ptLEbytes); err != nil {
		return fmt.Errorf("primary LE path table: %w", err)
	}
	if _, err := w.Write(l.ptMEbytes); err != nil {
		return fmt.Errorf("primary ME path table: %w", err)
	}

	// Joliet path tables, same padding rule.
	if _, err := w.Write(l.jolietPtLEbytes); err != nil {
		return fmt.Errorf("joliet LE path table: %w", err)
	}
	if _, err := w.Write(l.jolietPtMEbytes); err != nil {
		return fmt.Errorf("joliet ME path table: %w", err)
	}

	// Primary directory extents (BFS). Each extent may span multiple sectors.
	for _, d := range l.dirs {
		if err := writeDirExtent(w, d); err != nil {
			return fmt.Errorf("primary dir %q: %w", d.name, err)
		}
	}

	// Joliet directory extents (BFS, one sector each) — emitted BEFORE the CE
	// pool to match genisoimage's output order (dirtree → jdirtree → extension).
	for _, d := range l.dirs {
		if err := writeJolietDirExtent(w, d); err != nil {
			return fmt.Errorf("joliet dir %q: %w", d.name, err)
		}
	}

	// CE pool sectors (extension_desc in genisoimage, after Joliet dirs).
	for _, sector := range l.ce.sectors {
		if _, err := w.Write(sector); err != nil {
			return fmt.Errorf("CE pool sector: %w", err)
		}
	}

	// File data extents (shared — both trees reference these LBAs).
	for _, f := range l.files {
		if err := writeFileExtent(w, f); err != nil {
			return fmt.Errorf("file %q: %w", f.name, err)
		}
	}

	return nil
}

// encodeRootDirRecord encodes the 34-byte root directory record for use inside
// a PVD or SVD at offset 156. The lba and size parameters allow sharing the
// function for both primary (d.lba) and Joliet (d.jolietLBA) roots.
func encodeRootDirRecord(lba, size uint32, t time.Time) []byte {
	return encodeDirRecord([]byte{0x00}, lba, size, 0x02, t, nil)
}

// writeDirExtent writes the primary directory extent for d across
// d.size/sectorSize sectors. Records never straddle sector boundaries — when
// the next record would not fit in the current sector's remaining bytes, the
// sector is padded to its boundary with zeros and the record starts at the
// beginning of the next sector. The final sector is padded to its boundary.
//
// Rock Ridge System Use is read from the per-node cache populated by pass 1;
// this function never touches the CE allocator. Dot uses d.mtime; dotdot uses
// the parent's mtime (or d.mtime for root); each child uses its own mtime.
func writeDirExtent(w io.Writer, d *node) error {
	parentLBA, parentSize := primaryParentLBASize(d)
	dotdotMtime := dotDotMtime(d)

	records := make([][]byte, 0, 2+len(d.children))
	records = append(records,
		encodeDotRecord(d.lba, d.size, d.mtime, d.suAsDot),
		encodeDotDotRecord(parentLBA, parentSize, dotdotMtime, d.suAsDotDot),
	)
	for _, c := range d.children {
		records = append(records, encodeChildRecord(c, c.mtime, c.suAsChild))
	}

	totalSectors := int(d.size / sectorSize)
	return writeDirRecordsPadded(w, records, totalSectors)
}

// writeJolietDirExtent writes the Joliet directory extent for d. Joliet never
// carries SUSP. The extent may span multiple sectors when the
// directory has many children (each Joliet record is 34+UCS-2-name bytes).
// Timestamps follow the same per-node mtime semantics as the primary tree.
func writeJolietDirExtent(w io.Writer, d *node) error {
	parentJolietLBA, parentSize := jolietParentLBASize(d)
	dotdotMtime := dotDotMtime(d)

	jolietExtentSize := d.jolietSize
	jsectors := jolietExtentSize / sectorSize

	records := make([][]byte, 0, 2+len(d.children))
	records = append(records,
		encodeDotRecord(d.jolietLBA, jolietExtentSize, d.mtime, nil),
		encodeDotDotRecord(parentJolietLBA, parentSize, dotdotMtime, nil),
	)
	for _, c := range jolietSortedChildren(d.children) {
		records = append(records, encodeJolietChildRecord(c, c.mtime))
	}

	return writeDirRecordsPadded(w, records, int(jsectors))
}

// jolietSortedChildren returns a sorted copy of children using Joliet's
// UCS-2BE bytewise identifier ordering. This is intentionally independent from
// the primary-tree sort key (which uses fileID semantics).
func jolietSortedChildren(children []*node) []*node {
	ordered := make([]*node, len(children))
	copy(ordered, children)
	if len(ordered) < 2 {
		return ordered
	}

	keys := make(map[*node]string, len(ordered))
	for _, c := range ordered {
		keys[c] = string(encodeUCS2BE(c.name))
	}

	sort.SliceStable(ordered, func(i, j int) bool {
		ki := keys[ordered[i]]
		kj := keys[ordered[j]]
		if ki == kj {
			return ordered[i].insertionSeq < ordered[j].insertionSeq
		}
		return ki < kj
	})
	return ordered
}

// writeDirRecordsPadded lays records across totalSectors sectors, pad each
// sector boundary where the next record would otherwise straddle it.
func writeDirRecordsPadded(w io.Writer, records [][]byte, totalSectors int) error {
	buf := make([]byte, 0, totalSectors*sectorSize)
	used := 0
	for _, rec := range records {
		// Roll to next sector if the record would fill or overflow the current
		// sector's remaining space. genisoimage requires at least one byte of
		// padding after the last record in each sector (ECMA-119 §6.8.1.1: the
		// terminating zero byte counts as the pad), so we roll on >=, not >.
		if used > 0 && used+len(rec) >= sectorSize {
			// Pad to next sector.
			pad := sectorSize - used
			buf = append(buf, make([]byte, pad)...)
			used = 0
		}
		buf = append(buf, rec...)
		used += len(rec)
	}
	// Pad final sector.
	if used > 0 && used < sectorSize {
		buf = append(buf, make([]byte, sectorSize-used)...)
	}
	// Pad any remaining reserved sectors.
	for len(buf) < totalSectors*sectorSize {
		buf = append(buf, make([]byte, sectorSize)...)
	}
	// Trim to exact length in case records + padding overshot.
	if len(buf) > totalSectors*sectorSize {
		buf = buf[:totalSectors*sectorSize]
	}
	_, writeErr := w.Write(buf)
	if writeErr != nil {
		return fmt.Errorf("writing padded dir records: %w", writeErr)
	}
	return nil
}

// dotDotMtime returns the mtime to use for a directory's dotdot entry.
// Root's dotdot points at itself; all others use the parent's mtime.
func dotDotMtime(d *node) time.Time {
	if d.ptParent == nil {
		return d.mtime
	}
	return d.ptParent.mtime
}

// encodeChildRecord encodes a primary directory record for a child node,
// including the Rock Ridge System Use area su.
func encodeChildRecord(c *node, t time.Time, su []byte) []byte {
	var ident []byte
	var flags byte
	if c.isDir {
		ident = []byte(translateISO9660(c.name))
		flags = 0x02
	} else {
		ident = []byte(fileID(c.name))
		flags = 0x00
	}
	return encodeDirRecord(ident, c.lba, c.size, flags, t, su)
}

// encodeJolietChildRecord encodes a Joliet directory record for a child node.
// Files share the same LBA as the primary tree (file data is emitted once).
func encodeJolietChildRecord(c *node, t time.Time) []byte {
	var ident []byte
	var flags byte
	if c.isDir {
		ident = jolietDirID(c.name)
		flags = 0x02
		return encodeDirRecord(ident, c.jolietLBA, c.jolietSize, flags, t, nil)
	}
	ident = jolietFileID(c.name)
	flags = 0x00
	return encodeDirRecord(ident, c.lba, c.size, flags, t, nil)
}

// primaryParentLBASize returns the LBA and size of d's parent for primary tree.
func primaryParentLBASize(d *node) (lba, size uint32) {
	if d.ptParent == nil {
		return d.lba, d.size
	}
	return d.ptParent.lba, d.ptParent.size
}

// jolietParentLBASize returns the Joliet LBA and size of d's parent.
func jolietParentLBASize(d *node) (lba, size uint32) {
	if d.ptParent == nil {
		return d.jolietLBA, d.jolietSize
	}
	return d.ptParent.jolietLBA, d.ptParent.jolietSize
}

// writeFileExtent writes file data, padded to a sector boundary. A zero-byte
// file writes nothing (pass 1 reserves zero sectors for it — genisoimage
// ISO_BLOCKS(0)==0 behaviour).
func writeFileExtent(w io.Writer, f *node) error {
	if len(f.data) == 0 {
		return nil
	}
	if _, err := w.Write(f.data); err != nil {
		return fmt.Errorf("writing file extent: %w", err)
	}
	if rem := len(f.data) % sectorSize; rem != 0 {
		if _, err := w.Write(make([]byte, sectorSize-rem)); err != nil {
			return fmt.Errorf("padding file extent: %w", err)
		}
	}
	return nil
}

// writeZeroSectors writes n zero sectors to w.
func writeZeroSectors(w io.Writer, n int) error {
	sector := make([]byte, sectorSize)
	for range n {
		if _, err := w.Write(sector); err != nil {
			return fmt.Errorf("writing zero sector: %w", err)
		}
	}
	return nil
}
