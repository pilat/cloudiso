package cloudiso

import (
	"encoding/binary"
	"fmt"
	"time"
)

// encodePVD encodes the 2048-byte Primary Volume Descriptor per ECMA-119 §8.4.
//
// Field offsets are confirmed against the pycdlib headervd.py FMT string:
// '<B5sBB32s32sQLL32sHHHHHHLLLLLL34s128s128s128s128s37s37s37s17s17s17s17sBB512s653s'
//
//	 0   type=1
//	 1   "CD001"
//	 6   version=1
//	 7   flags=0 (unused for PVD)
//	 8   system_identifier (32, space-padded)
//	40   volume_identifier (32, space-padded)
//	72   unused (8 bytes, zero)
//	80   volume_space_size (both-order 4+4)
//	88   escape_sequences (32 bytes, zero for PVD)
//	120  set_size (both-order 2+2, value 1)
//	124  seqnum (both-order 2+2, value 1)
//	128  logical_block_size (both-order 2+2, value 2048)
//	132  path_table_size (both-order 4+4)
//	140  path_table_loc_le (4, little-endian)
//	144  opt_path_table_loc_le (4, zero)
//	148  path_table_loc_be (4, big-endian sector number)
//	152  opt_path_table_loc_be (4, zero)
//	156  root_dir_record (34 bytes)
//	190  volume_set_identifier (128, space-padded)
//	318  publisher_identifier (128, space-padded)
//	446  preparer_identifier (128, space-padded)
//	574  application_identifier (128, space-padded)
//	702  copyright_file_identifier (37, space-padded)
//	739  abstract_file_identifier (37, space-padded)
//	776  bibliographic_file_identifier (37, space-padded)
//	813  volume_creation_date (17, ASCII)
//	830  volume_modification_date (17, zeros)
//	847  volume_expiration_date (17, zeros)
//	864  volume_effective_date (17, zeros)
//	881  file_structure_version=1
//	882  unused=0
//	883  application_use (512, zeros)
//	1395 reserved (653, zeros)
func encodePVD(
	volumeID string,
	publisher string,
	preparer string,
	creationTime time.Time,
	totalSectors uint32,
	ptLEsector uint32,
	ptMEsector uint32,
	ptBytes uint32,
	rootDirRec []byte, // exactly 34 bytes
) ([sectorSize]byte, error) {
	if len(rootDirRec) != 34 {
		return [sectorSize]byte{}, fmt.Errorf("root dir record must be 34 bytes, got %d", len(rootDirRec))
	}
	var buf [sectorSize]byte

	// Type, identifier, version.
	buf[0] = 1
	copy(buf[1:6], "CD001")
	buf[6] = 1

	// System identifier: 32 space-padded (ECMA-119 §8.4.5).
	spacePad(buf[8:40])

	// Volume identifier: up to 32, space-padded (ECMA-119 §8.4.6).
	copySpacePad(buf[40:72], volumeID)

	// Volume space size (both-byte-order) — ECMA-119 §8.4.8.
	binary.LittleEndian.PutUint32(buf[80:84], totalSectors)
	binary.BigEndian.PutUint32(buf[84:88], totalSectors)

	// Escape sequences: 32 zero bytes (PVD has no escape sequences).

	// Volume set size = 1 (both-order) — ECMA-119 §8.4.10.
	binary.LittleEndian.PutUint16(buf[120:122], 1)
	binary.BigEndian.PutUint16(buf[122:124], 1)

	// Volume sequence number = 1 (both-order) — ECMA-119 §8.4.11.
	binary.LittleEndian.PutUint16(buf[124:126], 1)
	binary.BigEndian.PutUint16(buf[126:128], 1)

	// Logical block size = 2048 (both-order) — ECMA-119 §8.4.12.
	binary.LittleEndian.PutUint16(buf[128:130], sectorSize)
	binary.BigEndian.PutUint16(buf[130:132], sectorSize)

	// Path table size in bytes (both-order) — ECMA-119 §8.4.13.
	binary.LittleEndian.PutUint32(buf[132:136], ptBytes)
	binary.BigEndian.PutUint32(buf[136:140], ptBytes)

	// L-path table location (LE 32-bit) — ECMA-119 §8.4.14.
	binary.LittleEndian.PutUint32(buf[140:144], ptLEsector)
	// Optional L-path table: 0 — ECMA-119 §8.4.15.

	// M-path table location stored as big-endian 32-bit per ECMA-119 §8.4.16.
	// NOTE: the PVD field at offset 148 stores the M-path table location
	// as a big-endian integer (i.e. bytes are swapped vs. the LE field).
	binary.BigEndian.PutUint32(buf[148:152], ptMEsector)
	// Optional M-path table: 0 — ECMA-119 §8.4.17.

	// Root directory record (34 bytes) — ECMA-119 §8.4.18.
	copy(buf[156:190], rootDirRec)

	// Volume set identifier: space-padded 128 — ECMA-119 §8.4.19.
	spacePad(buf[190:318])

	// Publisher identifier: space-padded 128 — ECMA-119 §8.4.20.
	copySpacePad(buf[318:446], publisher)

	// Preparer identifier: space-padded — ECMA-119 §8.4.21.
	copySpacePad(buf[446:574], preparer)

	// Application identifier: "CLOUDISO" padded — ECMA-119 §8.4.22.
	copySpacePad(buf[574:702], "CLOUDISO")

	// Copyright, abstract, bibliographic file identifiers: space-padded.
	spacePad(buf[702:739])
	spacePad(buf[739:776])
	spacePad(buf[776:813])

	// Volume creation date (17 bytes ASCII + GMT) — ECMA-119 §8.4.26.1.
	encodeVDDate(buf[813:830], creationTime)

	// Modification date: genisoimage sets this equal to creation_date (write.c:1987).
	encodeVDDate(buf[830:847], creationTime)

	// Expiration date: genisoimage writes "0000000000000000\x00" (write.c:1988).
	// This is the ECMA-119 §8.4.26.1 empty form: 16 ASCII '0' chars + 0x00 GMT.
	encodeZeroVDDate(buf[847:864])

	// Effective date: genisoimage sets this equal to creation_date (write.c:1989).
	encodeVDDate(buf[864:881], creationTime)

	// File structure version = 1 — ECMA-119 §8.4.30.
	buf[881] = 1

	// Application use (512 bytes, offset 883..1395): space-filled per genisoimage.
	spacePad(buf[883:1395])
	// Reserved (offset 1395..2048, 653 bytes): zeros per ECMA-119 §8.4.32.

	return buf, nil
}

// encodeVDST encodes the 2048-byte Volume Descriptor Set Terminator per ECMA-119 §8.3.
func encodeVDST() [sectorSize]byte {
	var buf [sectorSize]byte
	buf[0] = 255
	copy(buf[1:6], "CD001")
	buf[6] = 1
	// remaining 2041 bytes are zero.
	return buf
}

// encodeVDDate encodes a time.Time into the 17-byte ASCII Volume Descriptor
// date format per ECMA-119 §8.4.26.1: "YYYYMMDDHHMMSSCC\x00" where CC is
// hundredths of a second (always "00") and the last byte is the GMT offset
// (always 0 = UTC).
func encodeVDDate(dst []byte, t time.Time) {
	t = t.UTC()
	s := fmt.Sprintf("%04d%02d%02d%02d%02d%02d00",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())
	copy(dst, s)
	dst[16] = 0 // GMT offset in 15-min units
}

// encodeZeroVDDate writes the ECMA-119 §8.4.26.1 "empty" date: 16 ASCII '0'
// characters (0x30) followed by 0x00 as the GMT-offset byte.
// genisoimage uses this form for the expiration_date field (write.c:1988).
func encodeZeroVDDate(dst []byte) {
	for i := range 16 {
		dst[i] = 0x30 // ASCII '0'
	}
	dst[16] = 0
}

// spacePad fills dst with ASCII spaces (0x20).
func spacePad(dst []byte) {
	for i := range dst {
		dst[i] = 0x20
	}
}

// copySpacePad copies src into dst and fills the remainder with 0x20.
func copySpacePad(dst []byte, src string) {
	n := copy(dst, src)
	for i := n; i < len(dst); i++ {
		dst[i] = 0x20
	}
}
