package cloudiso

import (
	"encoding/binary"
	"time"
)

// encodeSVD encodes the 2048-byte Supplementary Volume Descriptor (Joliet)
// per ECMA-119 §8.5 and the Joliet specification.
//
// The SVD is structurally identical to the PVD except:
//   - Type byte = 2 (supplementary).
//   - Escape sequences at offset 88: "%/E" (UCS-2 level 3).
//   - All a-character / d-character string fields are UCS-2BE encoded and
//     padded with UCS-2BE SPACE (0x00 0x20) pairs instead of ASCII 0x20.
//   - Root dir record points at the Joliet root directory extent.
//
// Field layout confirmed against pycdlib headervd.py FMT string and
// the genisoimage joliet.c get_joliet_vol_desc function.
func encodeSVD(
	volumeID string,
	publisher string,
	preparer string,
	creationTime time.Time,
	totalSectors uint32,
	ptLEsector uint32,
	ptMEsector uint32,
	ptBytes uint32,
	rootDirRec []byte, // exactly 34 bytes, pointing at Joliet root LBA
) [sectorSize]byte {
	var buf [sectorSize]byte

	// Type 2 = Supplementary Volume Descriptor. ECMA-119 §8.5.1.
	buf[0] = 2
	copy(buf[1:6], "CD001")
	buf[6] = 1
	// Offset 7: flags = 0 (not a bootable supplementary descriptor).

	// System Identifier (offset 8, 32 bytes): UCS-2BE padded.
	// genisoimage passes NULL (empty) — we do the same.
	copyUCS2BEPad(buf[8:40], "")

	// Volume Identifier (offset 40, 32 bytes): UCS-2BE of volumeID.
	copyUCS2BEPad(buf[40:72], volumeID)

	// Volume Space Size (offset 80, 8 bytes both-order) — ECMA-119 §8.4.8.
	binary.LittleEndian.PutUint32(buf[80:84], totalSectors)
	binary.BigEndian.PutUint32(buf[84:88], totalSectors)

	// Escape Sequences (offset 88, 32 bytes) — Joliet spec §3.
	// "%/E" = UCS-2 Level 3. Bytes: 0x25 0x2F 0x45, rest zeros.
	buf[88] = 0x25
	buf[89] = 0x2F
	buf[90] = 0x45

	// Volume Set Size = 1 (both-order) — ECMA-119 §8.4.10.
	binary.LittleEndian.PutUint16(buf[120:122], 1)
	binary.BigEndian.PutUint16(buf[122:124], 1)

	// Volume Sequence Number = 1 (both-order) — ECMA-119 §8.4.11.
	binary.LittleEndian.PutUint16(buf[124:126], 1)
	binary.BigEndian.PutUint16(buf[126:128], 1)

	// Logical Block Size = 2048 (both-order) — ECMA-119 §8.4.12.
	binary.LittleEndian.PutUint16(buf[128:130], sectorSize)
	binary.BigEndian.PutUint16(buf[130:132], sectorSize)

	// Path Table Size in bytes (both-order) — ECMA-119 §8.4.13.
	binary.LittleEndian.PutUint32(buf[132:136], ptBytes)
	binary.BigEndian.PutUint32(buf[136:140], ptBytes)

	// L-path table location (LE 32-bit) — ECMA-119 §8.4.14.
	binary.LittleEndian.PutUint32(buf[140:144], ptLEsector)
	// Optional L-path table: 0 (offset 144).

	// M-path table location (BE 32-bit) — ECMA-119 §8.4.16.
	binary.BigEndian.PutUint32(buf[148:152], ptMEsector)
	// Optional M-path table: 0 (offset 152).

	// Root Directory Record (offset 156, 34 bytes) — ECMA-119 §8.4.18.
	copy(buf[156:190], rootDirRec)

	// Volume Set Identifier (offset 190, 128 bytes): UCS-2BE of empty string
	// (space-padded). genisoimage sets this from -volset flag, which we pass
	// as '' (empty), so the field is all UCS-2BE spaces.
	copyUCS2BEPad(buf[190:318], "")

	// Publisher Identifier (offset 318, 128 bytes): UCS-2BE of publisher.
	copyUCS2BEPad(buf[318:446], publisher)

	// Data Preparer Identifier (offset 446, 128 bytes): UCS-2BE of preparer.
	copyUCS2BEPad(buf[446:574], preparer)

	// Application Identifier (offset 574, 128 bytes): UCS-2BE "CLOUDISO".
	copyUCS2BEPad(buf[574:702], "CLOUDISO")

	// Copyright, Abstract, Bibliographic File Identifiers (37 bytes each):
	// UCS-2BE padded empty strings.
	copyUCS2BEPad(buf[702:739], "")
	copyUCS2BEPad(buf[739:776], "")
	copyUCS2BEPad(buf[776:813], "")

	// Volume Creation Date (offset 813, 17 bytes ASCII) — ECMA-119 §8.4.26.1.
	// Date fields in SVD use the same ASCII format as PVD — NOT UCS-2.
	encodeVDDate(buf[813:830], creationTime)

	// Modification date: genisoimage sets equal to creation_date (write.c:1987).
	encodeVDDate(buf[830:847], creationTime)

	// Expiration date: genisoimage writes ECMA-119 empty form "0000000000000000\x00"
	// (write.c:1988).
	encodeZeroVDDate(buf[847:864])

	// Effective date: genisoimage sets equal to creation_date (write.c:1989).
	encodeVDDate(buf[864:881], creationTime)

	// File Structure Version = 1 (offset 881).
	buf[881] = 1

	// Application Use (offset 883..1395, 512 bytes): space-filled per genisoimage.
	spacePad(buf[883:1395])
	// Reserved (offset 1395..2048, 653 bytes): zeros per ECMA-119 §8.5.5.

	return buf
}

// copyUCS2BEPad encodes s as UCS-2BE and copies it into dst, then pads the
// remaining bytes with UCS-2BE SPACE pairs (0x00 0x20).
//
// dst must have even length. All characters in s must be in the BMP (≤U+FFFF).
// For the ASCII names used in this library each rune encodes to exactly two bytes:
// 0x00 followed by the ASCII byte value.
func copyUCS2BEPad(dst []byte, s string) {
	i := 0
	for _, r := range s {
		if i+1 >= len(dst) {
			break
		}
		dst[i] = byte(r >> 8)
		dst[i+1] = byte(r)
		i += 2
	}
	// Pad remainder with UCS-2BE SPACE (0x00 0x20).
	for ; i+1 < len(dst); i += 2 {
		dst[i] = 0x00
		dst[i+1] = 0x20
	}
}
