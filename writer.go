// Package cloudiso provides a write-only library for creating ISO 9660 disk
// images with Joliet and Rock Ridge extensions. The primary target is
// cloud-init seed ISOs (NoCloud cidata, OpenStack ConfigDrive v2 config-2).
//
// Usage:
//
//	fixed := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
//	w := &cloudiso.Writer{VolumeID: "cidata", Publisher: "my-service"}
//	_ = w.AddDir("/", fixed)
//	_ = w.AddFile("meta-data", metaData, fixed)
//	_ = w.AddFile("user-data", userData, fixed)
//	var buf bytes.Buffer
//	_ = w.Write(&buf)
package cloudiso

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Writer builds an ISO 9660 image. Build the tree with AddDir and AddFile,
// then call Write exactly once.
//
// Both a Joliet Supplementary Volume Descriptor tree and Rock Ridge (RRIP 1.12)
// SUSP records are always emitted — equivalent to mkisofs -J -r.
type Writer struct {
	// VolumeID is the volume identifier written into the Primary and Joliet
	// Volume Descriptors. Cloud-init NoCloud expects "cidata"; OpenStack
	// ConfigDrive v2 expects "config-2". Defaults to "CDROM" if empty.
	VolumeID string

	// Publisher is the Publisher Identifier field in the Primary and Joliet
	// Volume Descriptors (ECMA-119 §8.4.9). Up to 128 bytes; excess is
	// silently truncated during emit. Optional.
	Publisher string

	// Preparer is the Data Preparer Identifier field in the Primary and Joliet
	// Volume Descriptors (ECMA-119 §8.4.21). Up to 128 bytes; excess is
	// silently truncated during emit. Optional.
	Preparer string

	// CreationTime is stamped into the Primary and Joliet Volume Descriptors
	// as the Volume Creation Date and Time (ECMA-119 §8.4.26.1). Does not
	// affect any directory or file timestamps — use AddDir/AddFile mtime for
	// those. Defaults to time.Now().UTC() if zero.
	CreationTime time.Time

	root *node
}

// AddDir registers a directory at path with the given mtime. path must be "/"
// or "" to set the root mtime, or a slash-separated sequence of previously
// registered components. Each component must satisfy [A-Za-z0-9._-], length
// 1–31. "." and ".." are reserved and rejected.
//
// Parent directories must be registered via AddDir before any of their
// children. Registering the same path twice is an error.
//
// AddDir must not be called after Write.
func (w *Writer) AddDir(path string, mtime time.Time) error {
	// Root shorthand: "/" or "" both mean "set the root mtime".
	if path == "/" || path == "" {
		if w.root != nil {
			return fmt.Errorf("AddDir %q: duplicate entry (root already registered)", path)
		}
		w.root = &node{isDir: true, mtime: mtime}
		return nil
	}

	parts, err := splitPath(path)
	if err != nil {
		return fmt.Errorf("AddDir %q: %w", path, err)
	}
	for _, part := range parts {
		if err := validate(part); err != nil {
			return fmt.Errorf("AddDir %q: %w", path, err)
		}
	}

	if w.root == nil {
		return fmt.Errorf("AddDir %q: root not registered; call AddDir(\"/\", mtime) first", path)
	}

	if err := w.insertDir(parts, mtime); err != nil {
		return fmt.Errorf("AddDir %q: %w", path, err)
	}
	return nil
}

// AddFile adds a file at the given path (components separated by '/') with
// the given content and mtime. Each path component must satisfy
// [A-Za-z0-9._-], length 1–31. The strings "." and ".." are reserved and
// rejected.
//
// The parent directory must have been registered via AddDir before AddFile is
// called. This includes the root: AddDir("/", mtime) must be called before any
// AddFile.
//
// AddFile must not be called after Write.
func (w *Writer) AddFile(path string, data []byte, mtime time.Time) error {
	parts, err := splitPath(path)
	if err != nil {
		return fmt.Errorf("AddFile %q: %w", path, err)
	}

	for _, part := range parts {
		if err := validate(part); err != nil {
			return fmt.Errorf("AddFile %q: %w", path, err)
		}
	}

	if w.root == nil {
		return fmt.Errorf("AddFile %q: root not registered; call AddDir(\"/\", mtime) first", path)
	}

	if err := w.insertFile(parts, data, mtime); err != nil {
		return fmt.Errorf("AddFile %q: %w", path, err)
	}
	return nil
}

// insertDir walks to the parent directory of parts and inserts a new dir node.
// Parent must already exist; auto-mkdir is not performed.
func (w *Writer) insertDir(parts []string, mtime time.Time) error {
	cur := w.root
	for _, part := range parts[:len(parts)-1] {
		c := cur.findChild(part)
		if c == nil {
			return fmt.Errorf("parent directory %q does not exist", strings.Join(parts[:len(parts)-1], "/"))
		}
		if !c.isDir {
			return fmt.Errorf("path component %q is a file, not a directory", part)
		}
		cur = c
	}
	dirName := parts[len(parts)-1]
	// Check for conflict: a file with this name must not already exist.
	if existing := cur.findChild(dirName); existing != nil {
		if !existing.isDir {
			return fmt.Errorf("path component %q already exists as a file", dirName)
		}
		return fmt.Errorf("duplicate entry %q", dirName)
	}
	return cur.insertChild(dirName, true, nil, mtime)
}

// insertFile walks to the parent directory of parts and inserts the file node.
// Parent must already exist; auto-mkdir is not performed.
func (w *Writer) insertFile(parts []string, data []byte, mtime time.Time) error {
	cur := w.root
	for _, part := range parts[:len(parts)-1] {
		c := cur.findChild(part)
		if c == nil {
			return fmt.Errorf("parent directory %q does not exist", strings.Join(parts[:len(parts)-1], "/"))
		}
		if !c.isDir {
			return fmt.Errorf("path component %q is a file, not a directory", part)
		}
		cur = c
	}
	filename := parts[len(parts)-1]
	return cur.insertChild(filename, false, data, mtime)
}

// Write encodes the complete ISO 9660 image and writes it to out.
// The image size is always a multiple of 2048 bytes.
func (w *Writer) Write(out io.Writer) error {
	if w.root == nil {
		w.root = &node{isDir: true}
	}

	t := w.CreationTime
	if t.IsZero() {
		t = time.Now().UTC()
	}

	l, err := computeLayout(w.root)
	if err != nil {
		return fmt.Errorf("iso9660 layout: %w", err)
	}

	volumeID := w.VolumeID
	if volumeID == "" {
		volumeID = "CDROM"
	}
	publisher := w.Publisher
	preparer := w.Preparer

	if err := emit(out, l, volumeID, publisher, preparer, t); err != nil {
		return fmt.Errorf("iso9660 emit: %w", err)
	}
	return nil
}
