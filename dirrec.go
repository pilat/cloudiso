package cloudiso

import (
	"encoding/binary"
	"time"
)

// encodeDate7 encodes a time.Time into the 7-byte binary recording date
// format per ECMA-119 §9.1.5. GMT offset is always 0 (UTC).
func encodeDate7(t time.Time) [7]byte {
	t = t.UTC()
	return [7]byte{
		byte(t.Year() - 1900),
		byte(t.Month()),
		byte(t.Day()),
		byte(t.Hour()),
		byte(t.Minute()),
		byte(t.Second()),
		0, // GMT offset in 15-min units; 0 = UTC
	}
}

// encodeDirRecord encodes a single directory record per ECMA-119 §9.1 with an
// optional System Use area. su may be nil for Joliet records.
//
// Layout (all offsets from DR start):
//
//	0    len_dr  (1 byte)
//	1    xattr   (1 byte, always 0)
//	2    extent  (both-byte-order 4+4 = 8 bytes)
//	10   size    (both-byte-order 4+4 = 8 bytes)
//	18   date7   (7 bytes)
//	25   flags   (1 byte)
//	26   unit    (1 byte, 0)
//	27   gap     (1 byte, 0)
//	28   seqnum  (both-byte-order 2+2 = 4 bytes)
//	32   len_fi  (1 byte)
//	33   fi      (len_fi bytes)
//	33+len_fi  padding to even (0 or 1 zero byte)
//	...  System Use area (su bytes)
//	...  final pad to even total length (0 or 1 zero byte)
func encodeDirRecord(fileIdent []byte, extentLBA, dataSize uint32, flags byte, t time.Time, su []byte) []byte {
	lenFI := len(fileIdent)
	baseLen := drFixedLen + lenFI // 33 + lenFI
	// One padding byte after identifier if baseLen is odd (ECMA-119 §9.1.6).
	idPad := baseLen % 2 // 1 if odd, 0 if even
	// Total length including SU. The overall record length must be even
	// (ECMA-119 §9.1): add a trailing zero byte if needed.
	withSU := baseLen + idPad + len(su)
	suPad := withSU % 2 // 1 if odd total, 0 if even
	totalLen := withSU + suPad

	buf := make([]byte, totalLen)
	buf[0] = byte(totalLen)
	buf[1] = 0 // xattr length
	binary.LittleEndian.PutUint32(buf[2:6], extentLBA)
	binary.BigEndian.PutUint32(buf[6:10], extentLBA)
	binary.LittleEndian.PutUint32(buf[10:14], dataSize)
	binary.BigEndian.PutUint32(buf[14:18], dataSize)
	d := encodeDate7(t)
	copy(buf[18:25], d[:])
	buf[25] = flags
	buf[26] = 0 // file unit size
	buf[27] = 0 // interleave gap
	binary.LittleEndian.PutUint16(buf[28:30], 1)
	binary.BigEndian.PutUint16(buf[30:32], 1)
	buf[32] = byte(lenFI)
	copy(buf[33:], fileIdent)
	// idPad byte is already zero from make.
	if len(su) > 0 {
		copy(buf[33+lenFI+idPad:], su)
	}
	// suPad byte is already zero from make.
	return buf
}

// encodeDotRecord encodes the '.' directory entry for a directory at extentLBA
// with size dirSize. ECMA-119 §9.1 — identifier is 0x00, flags=0x02 (dir).
// su is the System Use area (may be nil for Joliet).
func encodeDotRecord(extentLBA, dirSize uint32, t time.Time, su []byte) []byte {
	return encodeDirRecord([]byte{0x00}, extentLBA, dirSize, 0x02, t, su)
}

// encodeDotDotRecord encodes the '..' directory entry.
// parentLBA is the extent LBA of the parent; parentSize is the parent dir extent size.
// su is the System Use area (may be nil for Joliet).
func encodeDotDotRecord(parentLBA, parentSize uint32, t time.Time, su []byte) []byte {
	return encodeDirRecord([]byte{0x01}, parentLBA, parentSize, 0x02, t, su)
}

// jolietFileID returns the UCS-2BE encoded Joliet file identifier:
// name encoded as UCS-2BE followed by ";1" encoded as UCS-2BE.
// Per the Joliet spec the version suffix is NOT appended for files on the
// Joliet tree — genisoimage omits ";1" from Joliet file names (joliet.c
// generate_one_joliet_directory: no version suffix is added).
func jolietFileID(name string) []byte {
	return encodeUCS2BE(name)
}

// jolietDirID returns the UCS-2BE encoded Joliet directory identifier.
func jolietDirID(name string) []byte {
	return encodeUCS2BE(name)
}

// encodeUCS2BE returns the UCS-2BE encoding of s. All characters must be
// in the BMP (≤U+FFFF); for ASCII input each byte becomes 0x00 + ascii_byte.
func encodeUCS2BE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r>>8), byte(r))
	}
	return out
}
