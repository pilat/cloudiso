package cloudiso

import (
	"encoding/binary"
)

// encodeJolietPathTables returns the LE and BE forms of the Joliet path table.
//
// Same structure as the primary path table (ECMA-119 §9.4) with two differences:
//   - Directory identifiers (di) are UCS-2BE encoded (2 bytes per ASCII char).
//   - Root record still uses the single byte 0x00 identifier per ECMA-119 §9.4.
//   - LBAs come from d.jolietLBA (not d.lba).
func encodeJolietPathTables(dirs []*node) (le, be []byte) {
	parentIdx := make(map[*node]uint16, len(dirs))
	for i, d := range dirs {
		parentIdx[d] = uint16(i + 1)
	}

	for i, d := range dirs {
		var di []byte
		if i == 0 {
			// Root: single byte 0x00, same as primary. ECMA-119 §9.4.
			di = []byte{0x00}
		} else {
			di = jolietDirID(d.name) // UCS-2BE
		}
		lenDI := len(di)
		padLen := lenDI % 2

		var parentNum uint16
		if i == 0 {
			parentNum = 1
		} else {
			parentNum = parentIdx[d.ptParent]
		}

		rec := make([]byte, 8+lenDI+padLen)
		rec[0] = byte(lenDI)
		rec[1] = 0
		binary.LittleEndian.PutUint32(rec[2:6], d.jolietLBA)
		binary.LittleEndian.PutUint16(rec[6:8], parentNum)
		copy(rec[8:], di)
		le = append(le, rec...)

		recBE := make([]byte, 8+lenDI+padLen)
		recBE[0] = byte(lenDI)
		recBE[1] = 0
		binary.BigEndian.PutUint32(recBE[2:6], d.jolietLBA)
		binary.BigEndian.PutUint16(recBE[6:8], parentNum)
		copy(recBE[8:], di)
		be = append(be, recBE...)
	}
	return le, be
}

// encodePathTables returns the LE and BE forms of the path table for the
// given directory list (BFS order, root first) and their 1-based directory
// numbers. parentNums maps each *node to its 1-based directory number in the
// BFS list.
//
// Path table record per ECMA-119 §9.4 (L-type, little-endian):
//
//	0   len_di  (1 byte) — length of directory identifier
//	1   xattr   (1 byte) — always 0
//	2   extent  (4 bytes LE for L-table, BE for M-table)
//	6   parent  (2 bytes LE for L-table, BE for M-table)
//	8   di      (len_di bytes)
//	8+len_di  0x00 pad if len_di is odd
//
// Root record has len_di=1 and di=0x00, parent=1 (self).
func encodePathTables(dirs []*node) (le, be []byte) {
	// parentIdx maps a *node pointer to its 1-based directory number.
	parentIdx := make(map[*node]uint16, len(dirs))
	for i, d := range dirs {
		parentIdx[d] = uint16(i + 1)
	}

	for i, d := range dirs {
		var di []byte
		if i == 0 {
			// Root: ECMA-119 §9.4 — identifier is one byte 0x00.
			di = []byte{0x00}
		} else {
			di = []byte(translateISO9660(d.name))
		}
		lenDI := len(di)
		padLen := lenDI % 2

		var parentNum uint16
		if i == 0 {
			parentNum = 1 // root's parent is itself
		} else {
			parentNum = parentIdx[d.ptParent]
		}

		// L-table record.
		rec := make([]byte, 8+lenDI+padLen)
		rec[0] = byte(lenDI)
		rec[1] = 0
		binary.LittleEndian.PutUint32(rec[2:6], d.lba)
		binary.LittleEndian.PutUint16(rec[6:8], parentNum)
		copy(rec[8:], di)
		le = append(le, rec...)

		// M-table record — same structure but extent and parent in big-endian.
		recBE := make([]byte, 8+lenDI+padLen)
		recBE[0] = byte(lenDI)
		recBE[1] = 0
		binary.BigEndian.PutUint32(recBE[2:6], d.lba)
		binary.BigEndian.PutUint16(recBE[6:8], parentNum)
		copy(recBE[8:], di)
		be = append(be, recBE...)
	}
	return le, be
}
