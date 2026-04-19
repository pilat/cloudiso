package cloudiso

// On-disk constants per ECMA-119.
const (
	sectorSize = 2048 // ECMA-119 §6.1 logical block size

	systemAreaSectors  = 16 // ECMA-119 §6.2.1 — reserved, zeros
	pvdSector          = 16 // Primary Volume Descriptor
	svdSector          = 17 // Supplementary Volume Descriptor (Joliet)
	vdstSector         = 18 // Volume Descriptor Set Terminator
	versionBlockSector = 19 // geniso-style version block (emitted as zeros)
	pathTableStart     = 20 // first path table LBA
)

// Directory record field sizes per ECMA-119 §9.1.
const (
	drFixedLen = 33 // bytes before the file identifier
	dotLen     = 34 // dot/dotdot entries are always 34 bytes
)

// maxDirRecordLen caps the declared LEN_DR of a directory record. ECMA-119
// §9.1 permits up to 255; we pin 254 (even) so the `byte(totalLen)` cast in
// encodeDirRecord never wraps to 0 when the record walks right to the
// boundary. mkisofs emits the same cap.
const maxDirRecordLen = 254
