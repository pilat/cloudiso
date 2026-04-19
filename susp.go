package cloudiso

import "encoding/binary"

// SUSP / RRIP record signatures (SUSP 1.12, RRIP 1.12).
const (
	suspSP_Len = 7  // SP record total length (SUSP §4.1)
	suspCE_Len = 28 // CE record total length (SUSP §5.1)
	rripPX_Len = 36 // PX record — genisoimage format: header(4)+mode(8)+nlink(8)+uid(8)+gid(8)
	rripTF_Len = 26 // TF record — 4-byte header + 3×7-byte timestamps (RRIP 1.12 §4.1.6)
	rripRR_Len = 5  // RR deprecated indicator (RRIP 1.12)
)

// ceAlloc manages the continuation-area pool that sits in a dedicated sector
// immediately after the last primary directory extent.
//
// During pass 1 (computeLayout), callers invoke alloc to reserve space for
// continuation bytes. alloc returns the (LBA, offset) at which the bytes will
// live. If the current sector fills up, a new sector is appended.
//
// The pool is emitted verbatim by emit, one sector at a time, between primary
// dirs and Joliet dirs.
type ceAlloc struct {
	baseLBA   uint32   // LBA of the first CE pool sector
	sectors   [][]byte // one entry per sector; each slice is exactly sectorSize bytes
	curSector int
	curOffset int
}

// newCEAlloc creates an allocator whose first sector is at baseLBA.
func newCEAlloc(baseLBA uint32) *ceAlloc {
	return &ceAlloc{
		baseLBA: baseLBA,
		sectors: [][]byte{make([]byte, sectorSize)},
	}
}

// alloc reserves n bytes in the pool and returns (lba, offset).
// It grows to a new sector if there is insufficient room in the current one.
func (a *ceAlloc) alloc(n int) (lba uint32, offset uint32) {
	if a.curOffset+n > sectorSize {
		// Current sector is full — open a new one.
		a.curSector++
		a.sectors = append(a.sectors, make([]byte, sectorSize))
		a.curOffset = 0
	}
	lba = a.baseLBA + uint32(a.curSector)
	offset = uint32(a.curOffset)
	a.curOffset += n
	return lba, offset
}

// write copies data into the pool at (lba, offset) returned by a prior alloc.
func (a *ceAlloc) write(lba uint32, offset uint32, data []byte) {
	idx := int(lba - a.baseLBA)
	copy(a.sectors[idx][offset:], data)
}

// sectorCount returns the number of sectors currently in the pool.
func (a *ceAlloc) sectorCount() int {
	return len(a.sectors)
}

// encodeSP encodes the 7-byte SUSP SP record (SUSP 1.12 §4.1).
// SP is emitted only in the root directory's dot self-entry.
func encodeSP() []byte {
	return []byte{
		'S', 'P', // signature
		suspSP_Len, // LEN = 7
		1,          // VER = 1
		0xBE, 0xEF, // check bytes
		0, // LEN_SKP = 0
	}
}

// encodeCE encodes the 28-byte SUSP CE record (SUSP 1.12 §5.1).
// extent is the LBA of the continuation sector; offset and length describe
// where within that sector the continuation data lives.
func encodeCE(extent, offset, length uint32) []byte {
	buf := make([]byte, suspCE_Len)
	buf[0] = 'C'
	buf[1] = 'E'
	buf[2] = suspCE_Len
	buf[3] = 1 // VER
	binary.LittleEndian.PutUint32(buf[4:8], extent)
	binary.BigEndian.PutUint32(buf[8:12], extent)
	binary.LittleEndian.PutUint32(buf[12:16], offset)
	binary.BigEndian.PutUint32(buf[16:20], offset)
	binary.LittleEndian.PutUint32(buf[20:24], length)
	binary.BigEndian.PutUint32(buf[24:28], length)
	return buf
}
