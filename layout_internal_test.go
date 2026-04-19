package cloudiso

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCECacheContract_NoAllocDuringEmit pins the invariant that pass 2 (emit)
// must not allocate from the CE pool. The current writer recomputes child SU
// during writeDirExtent — exposing a latent double-allocation if any record
// ever overflows. To force the overflow path with the existing 30-char name
// cap and fixed RRIP set, we shrink effectiveMaxDirRecordLen.
//
// Budget arithmetic (see plan §T1.8):
//
//	30-char name → lenFI=32, base=65, idPad=1
//	avail = 160 − 66 = 94
//	full SU = RR(5)+PX(36)+TF(26)+NM(35) = 102 → overflow
//	budget = 94 − 28(CE) = 66 → RR(5)+PX(36)=41 inline; TF+NM(61) → contSU
//
// 160 is the lowest safe value; below ~130 the buildSU budget math starves.
func TestCECacheContract_NoAllocDuringEmit(t *testing.T) {
	orig := effectiveMaxDirRecordLen
	effectiveMaxDirRecordLen = 160
	t.Cleanup(func() { effectiveMaxDirRecordLen = orig })

	t0 := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	root := &node{isDir: true, mtime: t0}
	name := strings.Repeat("a", 30)
	require.NoError(t, root.insertChild(name, false, []byte("x"), t0))

	l, err := computeLayout(root)
	require.NoError(t, err)

	// Precondition: pass 1 actually triggered overflow.
	require.Greater(t, l.ce.curOffset, 0,
		"pass 1 did not allocate any CE bytes — test precondition failed; check budget arithmetic")

	// Snapshot full CE state after pass 1.
	sectorsAfterPass1 := len(l.ce.sectors)
	offsetAfterPass1 := l.ce.curOffset
	curSectorAfterPass1 := l.ce.curSector
	bytesAfterPass1 := make([]byte, 0, sectorSize*len(l.ce.sectors))
	for _, s := range l.ce.sectors {
		bytesAfterPass1 = append(bytesAfterPass1, s...)
	}

	require.NoError(t, emit(io.Discard, l, "cetest", "", "", t0))

	// Structural invariants: pass 2 must not touch the allocator.
	require.Equal(t, sectorsAfterPass1, len(l.ce.sectors),
		"CE pool grew during emit — pass 2 allocated new sectors")
	require.Equal(t, offsetAfterPass1, l.ce.curOffset,
		"CE curOffset advanced during emit — pass 2 called ce.alloc")
	require.Equal(t, curSectorAfterPass1, l.ce.curSector,
		"CE curSector advanced during emit — pass 2 opened a new sector")

	// Byte-level invariant: pass 2 must not overwrite CE pool bytes.
	bytesAfterEmit := make([]byte, 0, sectorSize*len(l.ce.sectors))
	for _, s := range l.ce.sectors {
		bytesAfterEmit = append(bytesAfterEmit, s...)
	}
	require.True(t, bytes.Equal(bytesAfterPass1, bytesAfterEmit),
		"CE pool bytes changed during emit — pass 2 wrote to the pool")
}
