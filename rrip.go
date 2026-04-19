package cloudiso

import (
	"encoding/binary"
	"time"
)

// POSIX mode bits used for Rock Ridge PX records.
const (
	posixModeFile = uint32(0o100444) // S_IFREG | 0444 = 0x81A4
	posixModeDir  = uint32(0o040555) // S_IFDIR | 0555 = 0x41ED
)

// encodePX encodes the 36-byte PX record matching genisoimage 1.1.11
// (rock.c PX_SIZE=36). genisoimage uses the pre-RRIP-1.12 layout that
// omits the file_serial_number field: header(4)+mode(8)+nlink(8)+uid(8)+gid(8).
//
// uid and gid are always 0 (Rock Ridge rationalisation, mirrors mkisofs -r).
func encodePX(mode, nlink, uid, gid uint32) []byte {
	buf := make([]byte, rripPX_Len)
	buf[0] = 'P'
	buf[1] = 'X'
	buf[2] = rripPX_Len
	buf[3] = 1 // VER
	putBothUint32(buf[4:12], mode)
	putBothUint32(buf[12:20], nlink)
	putBothUint32(buf[20:28], uid)
	putBothUint32(buf[28:36], gid)
	return buf
}

// encodeTF encodes the 26-byte RRIP 1.12 TF record (§4.1.6) in 7-byte binary form.
// FLAGS = 0x0E: MODIFY (bit1) | ACCESS (bit2) | ATTRIBUTES (bit3). Matches
// genisoimage's default (no CREATION bit).
// mtime is used for MODIFY and ACCESS. ctime is used for ATTRIBUTES (inode
// change time); if ctime.IsZero(), ctime defaults to mtime.
func encodeTF(mtime, ctime time.Time) []byte {
	if ctime.IsZero() {
		ctime = mtime
	}
	buf := make([]byte, rripTF_Len)
	buf[0] = 'T'
	buf[1] = 'F'
	buf[2] = rripTF_Len
	buf[3] = 1    // VER
	buf[4] = 0x0E // FLAGS: MODIFY|ACCESS|ATTRIBUTES, LONG_FORM=0
	ts := encodeDate7(mtime)
	cs := encodeDate7(ctime)
	copy(buf[5:12], ts[:])  // MODIFY
	copy(buf[12:19], ts[:]) // ACCESS
	copy(buf[19:26], cs[:]) // ATTRIBUTES
	return buf
}

// encodeNM encodes the RRIP 1.12 NM (alternate name) record (§4.1.4).
// name must be the raw user-supplied component (UTF-8, no ";1" suffix).
// FLAGS = 0x00 (not CONTINUE, not CURRENT, not PARENT).
// Not emitted for dot/dotdot entries.
func encodeNM(name string) []byte {
	nb := []byte(name)
	buf := make([]byte, 5+len(nb))
	buf[0] = 'N'
	buf[1] = 'M'
	buf[2] = byte(5 + len(nb))
	buf[3] = 1    // VER
	buf[4] = 0x00 // FLAGS
	copy(buf[5:], nb)
	return buf
}

// encodeRR encodes the 5-byte RRIP RR deprecated-indicator record.
// flags encodes which RRIP fields are present:
//   - 0x01 = PX, 0x08 = NM, 0x80 = TF
//   - dot/dotdot (no NM): flags = 0x01|0x80 = 0x81
//   - regular children (PX+NM+TF): flags = 0x01|0x08|0x80 = 0x89
func encodeRR(flags byte) []byte {
	return []byte{
		'R', 'R',
		rripRR_Len,
		1,     // VER
		flags, // which RRIP fields present
	}
}

// encodeER encodes a SUSP 1.12 §5.5 Extension Reference record announcing the
// presence of an extension (here: RRIP). Text strings are copied verbatim
// from cdrkit-1.1.11's genisoimage.c:2921-2923.
//
// Layout: 'E' 'R' LEN_ER VER=1 LEN_ID LEN_DES LEN_SRC EXT_VER=1 ID DES SRC.
func encodeER(id, descriptor, source string) []byte {
	total := 8 + len(id) + len(descriptor) + len(source)
	buf := make([]byte, total)
	buf[0] = 'E'
	buf[1] = 'R'
	buf[2] = byte(total)
	buf[3] = 1
	buf[4] = byte(len(id))
	buf[5] = byte(len(descriptor))
	buf[6] = byte(len(source))
	buf[7] = 1
	off := 8
	off += copy(buf[off:], id)
	off += copy(buf[off:], descriptor)
	copy(buf[off:], source)
	return buf
}

// rripExtensionID, rripExtensionDescriptor and rripExtensionSource are the
// ER record strings emitted by genisoimage in the root dot entry's
// continuation area. Byte-matching genisoimage requires these exact texts;
// source: cdrkit-1.1.11/genisoimage/genisoimage.c:2921-2923.
const (
	rripExtensionID         = "RRIP_1991A"
	rripExtensionDescriptor = "THE ROCK RIDGE INTERCHANGE PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICS"
	rripExtensionSource     = "PLEASE CONTACT DISC PUBLISHER FOR SPECIFICATION SOURCE.  SEE PUBLISHER IDENTIFIER IN PRIMARY VOLUME DESCRIPTOR FOR CONTACT INFORMATION."
)

// rrFlagsForEntry returns the RR flags byte for a directory record.
// hasNM is true for child entries (not dot/dotdot).
func rrFlagsForEntry(hasNM bool) byte {
	if hasNM {
		return 0x89 // PX | NM | TF
	}
	return 0x81 // PX | TF only
}

// buildSU constructs the complete System Use bytes for a primary directory
// record. hasSP is true only for the root dot entry. hasNM is true for child
// entries (not dot/dotdot). hasER is true only for the root dot entry and
// carries the RRIP Extension Reference record into the CE pool.
//
// Returns (mainSU, contSU) where mainSU goes into the dir record and contSU
// (if non-nil) must be placed in the CE pool; if contSU is non-nil, mainSU
// already ends with a CE record pointing at ceExt/ceOff/len(contSU).
func buildSU(
	hasSP bool,
	hasNM bool,
	hasER bool,
	nmName string,
	mode, nlink uint32,
	t time.Time,
	ctime time.Time, // ATTRIBUTES field; if zero, defaults to t
	maxMain int, // max bytes available in the dir record SU area
	ceExt uint32, // CE extent LBA (used if overflow needed)
	ceOff uint32, // CE extent offset
) (mainSU, contSU []byte) {
	// Assemble all records in genisoimage 1.1.11 order:
	// [SP] RR [NM] PX TF [ER]
	var all [][]byte
	if hasSP {
		all = append(all, encodeSP())
	}
	all = append(all, encodeRR(rrFlagsForEntry(hasNM)))
	if hasNM {
		all = append(all, encodeNM(nmName))
	}
	all = append(all, encodePX(mode, nlink, 0, 0))
	all = append(all, encodeTF(t, ctime))
	if hasER {
		all = append(all, encodeER(rripExtensionID, rripExtensionDescriptor, rripExtensionSource))
	}

	// Try to fit everything in-line.
	total := 0
	for _, r := range all {
		total += len(r)
	}
	if total <= maxMain {
		// Everything fits — no CE needed.
		flat := make([]byte, 0, total)
		for _, r := range all {
			flat = append(flat, r...)
		}
		return flat, nil
	}

	// Overflow: keep as many whole records as fit in (maxMain - suspCE_Len),
	// move the rest to contSU. The CE record itself takes suspCE_Len bytes.
	budget := maxMain - suspCE_Len
	var mainRecs [][]byte
	var contRecs [][]byte
	used := 0
	for i, r := range all {
		if used+len(r) <= budget {
			mainRecs = append(mainRecs, r)
			used += len(r)
		} else {
			contRecs = all[i:]
			break
		}
	}

	// Build contSU.
	contLen := 0
	for _, r := range contRecs {
		contLen += len(r)
	}
	contSU = make([]byte, 0, contLen)
	for _, r := range contRecs {
		contSU = append(contSU, r...)
	}

	// Append CE record to main.
	mainRecs = append(mainRecs, encodeCE(ceExt, ceOff, uint32(len(contSU))))
	mainSU = make([]byte, 0, budget+suspCE_Len)
	for _, r := range mainRecs {
		mainSU = append(mainSU, r...)
	}
	return mainSU, contSU
}

// putBothUint32 writes v as both-order uint32: 4 bytes LE then 4 bytes BE into dst[0:8].
func putBothUint32(dst []byte, v uint32) {
	binary.LittleEndian.PutUint32(dst[0:4], v)
	binary.BigEndian.PutUint32(dst[4:8], v)
}

// computeNlinks sets node.nlink for every directory node.
// nlink for a dir = 2 + count of immediate child subdirectories.
// nlink for a file = 1.
func computeNlinks(root *node) {
	var walk func(*node)
	walk = func(n *node) {
		if !n.isDir {
			n.nlink = 1
			return
		}
		subdirCount := uint32(0)
		for _, c := range n.children {
			if c.isDir {
				subdirCount++
			}
		}
		n.nlink = 2 + subdirCount
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(root)
}
