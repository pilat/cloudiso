package cloudiso

import (
	"fmt"
	"sort"
	"time"
)

// node is a single entry in the in-memory directory tree.
type node struct {
	name         string // Level-1 component name (already validated)
	isDir        bool
	data         []byte  // nil for directories
	children     []*node // sorted by on-disk file identifier (ECMA-119 §9.3)
	mtime        time.Time
	insertionSeq int // order in which this node was inserted into its parent (0-based)

	// Assigned during pass 1 (computeLayout).
	lba        uint32 // primary directory or file extent LBA
	size       uint32 // primary data size (files) or dir extent size in bytes
	jolietLBA  uint32 // Joliet directory extent LBA (dirs only; files share lba)
	jolietSize uint32 // Joliet directory extent size in bytes (dirs only)
	ptParent   *node  // parent in BFS order; set by computeLayout for path table use
	nlink      uint32 // POSIX link count: 2+subdirs for dirs, 1 for files

	// SU bytes cached during layout pass 1. Pass 2 (emit) reads these fields
	// directly and never recomputes SU or allocates CE — guarding against the
	// double-allocation bug where pass 2 would re-invoke the compute helpers
	// with the same ceAlloc and overwrite the pool.
	//
	// suAsChild stays nil on the root node — root never appears as a child.
	suAsDot    []byte // for directories: SU for this dir's own dot (.)
	suAsDotDot []byte // for directories: SU for this dir's own dotdot (..)
	suAsChild  []byte // for non-root nodes: SU when this node is a child
}

func (n *node) insertChild(name string, isDir bool, data []byte, mtime time.Time) error {
	for _, c := range n.children {
		if c.name == name {
			return fmt.Errorf("duplicate entry %q", name)
		}
	}
	child := &node{name: name, isDir: isDir, data: data, mtime: mtime, insertionSeq: len(n.children)}
	n.children = append(n.children, child)
	// Keep sorted for deterministic output. ECMA-119 §9.3: sort by padded
	// d-characters, space-padded to equal length, compared bytewise.
	// For strict Level-1 upper-case names this is equivalent to bytewise
	// lexicographic order of the file identifier strings.
	sort.Slice(n.children, func(i, j int) bool {
		return n.children[i].sortKey() < n.children[j].sortKey()
	})
	return nil
}

// findChild returns the named child node, or nil if absent.
func (n *node) findChild(name string) *node {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

// sortKey returns the on-disk file identifier used for directory-record
// ordering per ECMA-119 §9.3 (bytewise compare of identifiers, space-padded
// to equal length). Files carry the ";1" version suffix; dirs do not. The
// ';' (0x3B) in file identifiers sorts above '-' (0x2D) and '.' (0x2E), so a
// file named "meta" will sort after a sibling dir "meta-data" — matching
// what genisoimage emits.
func (n *node) sortKey() string {
	if n.isDir {
		return n.name
	}
	return fileID(n.name)
}

// bfsOrder returns all directory nodes in breadth-first order, root first,
// children sorted alphabetically within each level. This order is used for
// path table record emission (ECMA-119 §9.4 requires parent numbers to be
// assigned level-by-level, with parents appearing before their children).
func bfsOrder(root *node) []*node {
	var result []*node
	queue := []*node{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		result = append(result, cur)
		for _, c := range cur.children {
			if c.isDir {
				queue = append(queue, c)
			}
		}
	}
	return result
}

// dfsReverseInsertOrder returns all directory nodes in depth-first pre-order,
// processing sibling directories in reverse insertion order at each level.
//
// This matches genisoimage 1.1.11's assign_directory_addresses traversal as
// reproduced in the byte-match test environment. The test fixtures
// are created by copying a host directory tree into a Linux tmpfs via Docker
// Desktop VirtioFS. Linux tmpfs readdir returns entries in creation order
// (hash-chain order following inode assignment). genisoimage processes
// siblings in the order readdir returns them, which corresponds to the order
// the entries were created on disk — i.e. the order they appear in the test
// fixture's Entries slice (AddDir/AddFile call order). Because
// assign_directory_addresses recurses by pushing children onto a stack (last
// first, visit first), the effective LBA assignment order is the reverse of
// the creation/insertion sequence.
func dfsReverseInsertOrder(root *node) []*node {
	var result []*node
	var walk func(*node)
	walk = func(d *node) {
		result = append(result, d)
		// Collect directory children and sort by insertionSeq descending
		// (reverse creation order). Children are stored in alpha order;
		// insertionSeq carries the original insertion position.
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
			walk(c)
		}
	}
	walk(root)
	return result
}
