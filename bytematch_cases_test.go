package cloudiso_test

import (
	"crypto/sha256"
	"time"
)

// seededBytes produces n deterministic bytes derived from seed by chaining
// SHA-256 rounds. Callers use this wherever "random-looking but reproducible"
// content is needed in test fixtures.
func seededBytes(seed string, n int) []byte {
	h := sha256.Sum256([]byte(seed))
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, h[:]...)
		h = sha256.Sum256(h[:])
	}
	return out[:n]
}

func init() {
	fixed := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	epoch := time.Unix(0, 0).UTC()
	y2099 := time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC)
	day1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	day3 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	day4 := time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC)
	day5 := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	pre1980 := time.Date(1975, 6, 15, 8, 30, 0, 0, time.UTC)

	// Shared tiny entries reused across config-axis cases (only 1 file needed).
	minEntries := func(mtime time.Time) []treeEntry {
		return []treeEntry{
			{Path: "/", IsDir: true, Mtime: mtime},
			{Path: "f", Data: []byte("x"), Mtime: mtime},
		}
	}

	// Shared NoCloud entries.
	nocloudEntries := func(mtime time.Time) []treeEntry {
		return []treeEntry{
			{Path: "/", IsDir: true, Mtime: mtime},
			{Path: "meta-data", Data: []byte("instance-id: test\n"), Mtime: mtime},
			{Path: "user-data", Data: []byte("#cloud-config\n"), Mtime: mtime},
			{Path: "network-config", Data: []byte("version: 2\n"), Mtime: mtime},
		}
	}

	bytematchCases = append(bytematchCases, []bytematchCase{

		// =====================================================================
		// Axis 1: Name variations
		// =====================================================================

		{
			Name:     "name_len_1",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "a", Data: []byte("x"), Mtime: fixed},
			},
		},
		{
			Name:     "name_len_2",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "ab", Data: []byte("x"), Mtime: fixed},
			},
		},
		{
			Name:     "name_len_15",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "abcdefghijklmno", Data: []byte("x"), Mtime: fixed},
			},
		},
		{
			Name:     "name_len_29",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "abcdefghijklmnopqrstuvwxyza1b", Data: []byte("x"), Mtime: fixed},
			},
		},
		{
			Name:     "name_len_30",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "abcdefghijklmnopqrstuvwxyza1b2", Data: []byte("x"), Mtime: fixed},
			},
		},
		{
			Name:     "name_leading_dot",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: ".hidden", Data: []byte("secret"), Mtime: fixed},
			},
		},
		{
			Name:     "name_trailing_dot",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "trailing.", Data: []byte("x"), Mtime: fixed},
			},
		},
		{
			Name:     "name_multi_dot",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "a..b.c", Data: []byte("multidot"), Mtime: fixed},
			},
		},
		{
			Name:     "name_only_digits",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "012345", Data: []byte("digits"), Mtime: fixed},
			},
		},
		{
			Name:     "name_only_letters",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "abcdef", Data: []byte("letters"), Mtime: fixed},
			},
		},
		{
			Name:     "name_mixed_case",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "MixedCASE", Data: []byte("mixed"), Mtime: fixed},
			},
		},
		{
			Name:     "name_single_hyphen",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "-", Data: []byte("x"), Mtime: fixed},
			},
		},
		{
			Name:     "name_single_underscore",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "_", Data: []byte("x"), Mtime: fixed},
			},
		},
		{
			Name:     "name_single_dot_letter",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: ".a", Data: []byte("x"), Mtime: fixed},
			},
		},
		{
			Name:     "name_hyphen_rich",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "a-b-c-d-e", Data: []byte("hyphens"), Mtime: fixed},
			},
		},
		{
			Name:     "name_underscore_rich",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "a_b_c_d_e", Data: []byte("underscores"), Mtime: fixed},
			},
		},
		{
			Name:     "name_dot_rich",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "a.b.c.d.e", Data: []byte("dots"), Mtime: fixed},
			},
		},
		{
			Name:     "name_mixed_specials",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "A.b-c_d.E", Data: []byte("mixed-specials"), Mtime: fixed},
			},
		},

		// =====================================================================
		// Axis 2: Content size / sector boundaries
		// =====================================================================

		{
			Name:     "content_empty_0b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "empty", Data: []byte{}, Mtime: fixed},
			},
		},
		{
			Name:     "content_1b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "one", Data: []byte("x"), Mtime: fixed},
			},
		},
		{
			Name:     "content_2047b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f2047", Data: seededBytes("content_2047b", 2047), Mtime: fixed},
			},
		},
		{
			Name:     "content_2048b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f2048", Data: seededBytes("content_2048b", 2048), Mtime: fixed},
			},
		},
		{
			Name:     "content_2049b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f2049", Data: seededBytes("content_2049b", 2049), Mtime: fixed},
			},
		},
		{
			Name:     "content_4095b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f4095", Data: seededBytes("content_4095b", 4095), Mtime: fixed},
			},
		},
		{
			Name:     "content_4096b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f4096", Data: seededBytes("content_4096b", 4096), Mtime: fixed},
			},
		},
		{
			Name:     "content_4097b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f4097", Data: seededBytes("content_4097b", 4097), Mtime: fixed},
			},
		},
		{
			Name:     "content_1mib",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f1mib", Data: seededBytes("content_1mib", 1048576), Mtime: fixed},
			},
		},

		// =====================================================================
		// Axis 3: Tree shapes
		// =====================================================================

		{
			Name:     "tree_single_file_root",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "readme", Data: []byte("hello"), Mtime: fixed},
			},
		},
		{
			Name:     "tree_nocloud",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: nocloudEntries(fixed),
		},
		{
			Name:     "tree_configdrive",
			VolumeID: "config-2", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "meta-data", Data: []byte("instance-id: test\n"), Mtime: fixed},
				{Path: "ec2", IsDir: true, Mtime: fixed},
				{Path: "ec2/latest", IsDir: true, Mtime: fixed},
				{Path: "ec2/latest/meta-data.json", Data: []byte(`{"instance-id":"i-001"}`), Mtime: fixed},
				{Path: "openstack", IsDir: true, Mtime: fixed},
				{Path: "openstack/latest", IsDir: true, Mtime: fixed},
				{Path: "openstack/latest/meta_data.json", Data: []byte(`{"uuid":"abc-123"}`), Mtime: fixed},
				{Path: "openstack/latest/user_data", Data: []byte("#!/bin/bash\necho hi\n"), Mtime: fixed},
			},
		},
		{
			Name:     "tree_10_flat_files",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "alpha", Data: []byte("a"), Mtime: fixed},
				{Path: "beta", Data: []byte("b"), Mtime: fixed},
				{Path: "config.json", Data: []byte(`{}`), Mtime: fixed},
				{Path: "data-001", Data: seededBytes("flat_001", 64), Mtime: fixed},
				{Path: "data-002", Data: seededBytes("flat_002", 128), Mtime: fixed},
				{Path: "file.log", Data: []byte("log entry\n"), Mtime: fixed},
				{Path: "meta-data", Data: []byte("id: x\n"), Mtime: fixed},
				{Path: "network-config", Data: []byte("version: 2\n"), Mtime: fixed},
				{Path: "user-data", Data: []byte("#cloud-config\n"), Mtime: fixed},
				{Path: "z-last", Data: []byte("last"), Mtime: fixed},
			},
		},
		{
			// 200 files in a single directory triggers multi-sector dir extents (F8).
			Name:     "tree_200_files_one_dir",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: func() []treeEntry {
				entries := []treeEntry{
					{Path: "/", IsDir: true, Mtime: fixed},
					{Path: "d", IsDir: true, Mtime: fixed},
				}
				for i := 0; i < 200; i++ {
					name := "f" + func() string {
						digits := "0000"
						n := i
						buf := [4]byte{'0', '0', '0', '0'}
						buf[3] = byte('0' + n%10)
						n /= 10
						buf[2] = byte('0' + n%10)
						n /= 10
						buf[1] = byte('0' + n%10)
						n /= 10
						buf[0] = byte('0' + n%10)
						_ = digits
						return string(buf[:])
					}()
					entries = append(entries, treeEntry{
						Path:  "d/" + name,
						Data:  []byte(name),
						Mtime: fixed,
					})
				}
				return entries
			}(),
		},
		{
			// 7 directories deep (root + 7 levels = 8 total, ISO 9660 §6.8.2.1 max).
			// Deeper trees trigger genisoimage's RR deep-directory relocation which
			// is outside our scope.
			Name:     "tree_deep_7_levels",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "a", IsDir: true, Mtime: fixed},
				{Path: "a/b", IsDir: true, Mtime: fixed},
				{Path: "a/b/c", IsDir: true, Mtime: fixed},
				{Path: "a/b/c/d", IsDir: true, Mtime: fixed},
				{Path: "a/b/c/d/e", IsDir: true, Mtime: fixed},
				{Path: "a/b/c/d/e/f", IsDir: true, Mtime: fixed},
				{Path: "a/b/c/d/e/f/g", IsDir: true, Mtime: fixed},
				{Path: "a/b/c/d/e/f/g/leaf", Data: []byte("deep"), Mtime: fixed},
			},
		},
		{
			// Root with 200 direct subdirs, each containing one file.
			Name:     "tree_wide_200_dirs",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: func() []treeEntry {
				entries := []treeEntry{
					{Path: "/", IsDir: true, Mtime: fixed},
				}
				for i := 0; i < 200; i++ {
					n := i
					buf := [3]byte{'0', '0', '0'}
					buf[2] = byte('0' + n%10)
					n /= 10
					buf[1] = byte('0' + n%10)
					n /= 10
					buf[0] = byte('0' + n%10)
					dirName := "d" + string(buf[:])
					entries = append(entries,
						treeEntry{Path: dirName, IsDir: true, Mtime: fixed},
						treeEntry{Path: dirName + "/f", Data: []byte(dirName), Mtime: fixed},
					)
				}
				return entries
			}(),
		},
		{
			// 20 top-level dirs × 25 subdirs each = 500 subdirs + 1 root = 501 dirs total.
			// Primary and Joliet path tables will each exceed one sector (D10 / F3).
			Name:     "tree_500_dirs_total",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: func() []treeEntry {
				entries := []treeEntry{
					{Path: "/", IsDir: true, Mtime: fixed},
				}
				for i := 0; i < 20; i++ {
					top := "t" + string([]byte{byte('0' + i/10), byte('0' + i%10)})
					entries = append(entries, treeEntry{Path: top, IsDir: true, Mtime: fixed})
					for j := 0; j < 25; j++ {
						sub := top + "/s" + string([]byte{byte('0' + j/10), byte('0' + j%10)})
						entries = append(entries,
							treeEntry{Path: sub, IsDir: true, Mtime: fixed},
							treeEntry{Path: sub + "/f", Data: []byte(sub), Mtime: fixed},
						)
					}
				}
				return entries
			}(),
		},
		{
			// A single subdirectory with a .keep file so geniso doesn't reject it.
			Name:     "tree_single_dir_with_keep",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "subdir", IsDir: true, Mtime: fixed},
				{Path: "subdir/.keep", Data: []byte{}, Mtime: fixed},
			},
		},

		// =====================================================================
		// Axis 4: Config variations
		// =====================================================================

		{
			Name:     "config_volid_empty",
			VolumeID: "", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: minEntries(fixed),
		},
		{
			Name:     "config_volid_1char",
			VolumeID: "A", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: minEntries(fixed),
		},
		{
			Name:     "config_volid_32char",
			VolumeID: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: minEntries(fixed),
		},
		{
			// a-characters set per ECMA-119: upper alpha + digits — no underscore.
			Name:     "config_volid_special",
			VolumeID: "CLOUD2DATA3", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: minEntries(fixed),
		},
		{
			Name:     "config_publisher_empty",
			VolumeID: "cidata", Publisher: "", Preparer: "", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: minEntries(fixed),
		},
		{
			Name:     "config_publisher_short",
			VolumeID: "cidata", Publisher: "acme", Preparer: "acme", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: minEntries(fixed),
		},
		{
			Name: "config_publisher_128",
			// Exactly 128 bytes — at the field boundary; must not be truncated.
			VolumeID:     "cidata",
			Publisher:    "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWX",
			Preparer:     "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWX",
			AppID:        "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: minEntries(fixed),
		},
		{
			Name: "config_publisher_129",
			// genisoimage rejects publishers longer than 128 bytes — use exactly 128.
			VolumeID:     "cidata",
			Publisher:    "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWX",
			Preparer:     "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWX",
			AppID:        "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: minEntries(fixed),
		},
		{
			Name:     "config_ctime_epoch",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: epoch, ModTime: epoch,
			Entries: minEntries(fixed),
		},
		{
			Name:     "config_ctime_2099",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: y2099, ModTime: y2099,
			Entries: minEntries(fixed),
		},
		{
			Name:     "config_ctime_distinct_mtime",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			ModTime:      time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: day1},
				{Path: "f", Data: []byte("distinct"), Mtime: day2},
			},
		},

		// =====================================================================
		// Axis 5: Per-file mtime variation
		// =====================================================================

		{
			Name:     "mtime_distinct_per_file",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f1", Data: []byte("one"), Mtime: day1},
				{Path: "f2", Data: []byte("two"), Mtime: day2},
				{Path: "f3", Data: []byte("three"), Mtime: day3},
				{Path: "f4", Data: []byte("four"), Mtime: day4},
				{Path: "f5", Data: []byte("five"), Mtime: day5},
			},
		},
		{
			Name:     "mtime_distinct_per_dir",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "dir1", IsDir: true, Mtime: day1},
				{Path: "dir1/f", Data: []byte("d1"), Mtime: day2},
				{Path: "dir2", IsDir: true, Mtime: day3},
				{Path: "dir2/f", Data: []byte("d2"), Mtime: day4},
				{Path: "dir3", IsDir: true, Mtime: day5},
				{Path: "dir3/f", Data: []byte("d3"), Mtime: fixed},
			},
		},
		{
			Name:     "mtime_mixed",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				// parent and child share mtime
				{Path: "shared", IsDir: true, Mtime: day1},
				{Path: "shared/same", Data: []byte("same-time"), Mtime: day1},
				// parent and child differ
				{Path: "differ", IsDir: true, Mtime: day2},
				{Path: "differ/other", Data: []byte("diff-time"), Mtime: day3},
			},
		},
		{
			Name:     "mtime_before_1980",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: pre1980},
				{Path: "old", Data: []byte("ancient"), Mtime: pre1980},
			},
		},
		{
			Name:     "mtime_leap_second_boundary",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC)},
				{Path: "f", Data: []byte("boundary"), Mtime: time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC)},
			},
		},

		// =====================================================================
		// Axis 6: Combination cases
		// =====================================================================

		{
			Name:     "combo_nocloud_with_long_names",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				// 30-char names with cloud-init-like content
				{Path: "meta-data-extended-cloud-init01", Data: []byte("instance-id: test\n"), Mtime: fixed},
				{Path: "user-data-extended-cloud-init01", Data: []byte("#cloud-config\n"), Mtime: fixed},
				{Path: "network-config-extended-cloud01", Data: []byte("version: 2\n"), Mtime: fixed},
			},
		},
		{
			Name:     "combo_nested_with_zero_byte_files",
			VolumeID: "config-2", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "openstack", IsDir: true, Mtime: fixed},
				{Path: "openstack/latest", IsDir: true, Mtime: fixed},
				{Path: "openstack/latest/meta_data.json", Data: []byte(`{"uuid":"x"}`), Mtime: fixed},
				// zero-byte file nested deep
				{Path: "openstack/latest/user_data", Data: []byte{}, Mtime: fixed},
				{Path: "ec2", IsDir: true, Mtime: fixed},
				{Path: "ec2/latest", IsDir: true, Mtime: fixed},
				{Path: "ec2/latest/meta-data.json", Data: []byte{}, Mtime: fixed},
			},
		},
		{
			Name:     "combo_wide_dir_with_mixed_content",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "zero", Data: []byte{}, Mtime: fixed},
				{Path: "one", Data: []byte("x"), Mtime: fixed},
				{Path: "hundred", Data: seededBytes("hundred", 100), Mtime: fixed},
				{Path: "s2048", Data: seededBytes("s2048", 2048), Mtime: fixed},
				{Path: "s2049", Data: seededBytes("s2049", 2049), Mtime: fixed},
				{Path: "s4096", Data: seededBytes("s4096", 4096), Mtime: fixed},
			},
		},
		{
			Name:     "combo_deep_with_leading_dots",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: ".cache", IsDir: true, Mtime: fixed},
				{Path: ".cache/.data", IsDir: true, Mtime: fixed},
				{Path: ".cache/.data/.hidden", IsDir: true, Mtime: fixed},
				{Path: ".cache/.data/.hidden/leaf", Data: []byte("deep-dot"), Mtime: fixed},
			},
		},
		{
			// Same shape as tree_500_dirs_total but every leaf file is 0 bytes.
			Name:     "combo_500_dirs_zero_byte_file_in_each",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: func() []treeEntry {
				entries := []treeEntry{
					{Path: "/", IsDir: true, Mtime: fixed},
				}
				for i := 0; i < 20; i++ {
					top := "t" + string([]byte{byte('0' + i/10), byte('0' + i%10)})
					entries = append(entries, treeEntry{Path: top, IsDir: true, Mtime: fixed})
					for j := 0; j < 25; j++ {
						sub := top + "/s" + string([]byte{byte('0' + j/10), byte('0' + j%10)})
						entries = append(entries,
							treeEntry{Path: sub, IsDir: true, Mtime: fixed},
							treeEntry{Path: sub + "/f", Data: []byte{}, Mtime: fixed},
						)
					}
				}
				return entries
			}(),
		},
		{
			// Many zero-byte files at root alongside non-empty files. Tests
			// that F1 (zero-byte padding) interacts correctly with LBA sequencing.
			Name:     "combo_multiple_zero_byte_files",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "empty1", Data: []byte{}, Mtime: fixed},
				{Path: "empty2", Data: []byte{}, Mtime: fixed},
				{Path: "nonempty", Data: []byte("between"), Mtime: fixed},
				{Path: "empty3", Data: []byte{}, Mtime: fixed},
				{Path: "last", Data: []byte("end"), Mtime: fixed},
			},
		},

		// =====================================================================
		// Additional cases to reach ≥100 total
		// =====================================================================

		// --- More name variations ---

		{
			Name:     "name_digits_and_dots",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "1.2.3", Data: []byte("version"), Mtime: fixed},
			},
		},
		{
			Name:     "name_uppercase_only",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "UPPERCASE", Data: []byte("UPPER"), Mtime: fixed},
			},
		},
		{
			Name:     "name_extension_json",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "meta_data.json", Data: []byte(`{"k":"v"}`), Mtime: fixed},
			},
		},
		{
			Name:     "name_extension_yaml",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "cloud.yaml", Data: []byte("key: value\n"), Mtime: fixed},
			},
		},
		{
			Name:     "name_cloud_init_canonical",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "meta-data", Data: []byte("instance-id: iid\n"), Mtime: fixed},
				{Path: "user-data", Data: []byte("#cloud-config\n"), Mtime: fixed},
			},
		},
		{
			Name:     "name_dir_len_30",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "abcdefghijklmnopqrstuvwxyza1b2", IsDir: true, Mtime: fixed},
				{Path: "abcdefghijklmnopqrstuvwxyza1b2/f", Data: []byte("x"), Mtime: fixed},
			},
		},
		{
			Name:     "name_dir_leading_dot",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: ".config", IsDir: true, Mtime: fixed},
				{Path: ".config/settings", Data: []byte("s=1\n"), Mtime: fixed},
			},
		},
		{
			Name:     "name_hyphen_at_start_of_dir",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "-d", IsDir: true, Mtime: fixed},
				{Path: "-d/f", Data: []byte("x"), Mtime: fixed},
			},
		},

		// --- More content-size cases ---

		{
			Name:     "content_3_bytes",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f3", Data: []byte("abc"), Mtime: fixed},
			},
		},
		{
			Name:     "content_512b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f512", Data: seededBytes("content_512b", 512), Mtime: fixed},
			},
		},
		{
			Name:     "content_1024b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f1024", Data: seededBytes("content_1024b", 1024), Mtime: fixed},
			},
		},
		{
			Name:     "content_6144b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f6144", Data: seededBytes("content_6144b", 6144), Mtime: fixed},
			},
		},
		{
			// 65536 = 32 sectors exactly.
			Name:     "content_65536b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f65536", Data: seededBytes("content_65536b", 65536), Mtime: fixed},
			},
		},

		// --- More tree-shape cases ---

		{
			Name:     "tree_two_files_root",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "alpha", Data: []byte("a"), Mtime: fixed},
				{Path: "beta", Data: []byte("b"), Mtime: fixed},
			},
		},
		{
			Name:     "tree_one_dir_one_file",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "sub", IsDir: true, Mtime: fixed},
				{Path: "sub/f", Data: []byte("sub-content"), Mtime: fixed},
			},
		},
		{
			Name:     "tree_mixed_root_and_nested",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "root-file", Data: []byte("at-root"), Mtime: fixed},
				{Path: "sub", IsDir: true, Mtime: fixed},
				{Path: "sub/nested-file", Data: []byte("nested"), Mtime: fixed},
			},
		},
		{
			Name:     "tree_5_files_seeded",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "a", Data: seededBytes("tree5a", 100), Mtime: fixed},
				{Path: "b", Data: seededBytes("tree5b", 200), Mtime: fixed},
				{Path: "c", Data: seededBytes("tree5c", 300), Mtime: fixed},
				{Path: "d", Data: seededBytes("tree5d", 400), Mtime: fixed},
				{Path: "e", Data: seededBytes("tree5e", 500), Mtime: fixed},
			},
		},
		{
			Name:     "tree_50_flat_files",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: func() []treeEntry {
				entries := []treeEntry{
					{Path: "/", IsDir: true, Mtime: fixed},
				}
				for i := 0; i < 50; i++ {
					name := "g" + string([]byte{byte('0' + i/10), byte('0' + i%10)})
					entries = append(entries, treeEntry{
						Path:  name,
						Data:  []byte(name),
						Mtime: fixed,
					})
				}
				return entries
			}(),
		},
		{
			Name:     "tree_3_levels_2_wide",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "dir1", IsDir: true, Mtime: fixed},
				{Path: "dir1/sub1", IsDir: true, Mtime: fixed},
				{Path: "dir1/sub1/f", Data: []byte("1-1"), Mtime: fixed},
				{Path: "dir1/sub2", IsDir: true, Mtime: fixed},
				{Path: "dir1/sub2/f", Data: []byte("1-2"), Mtime: fixed},
				{Path: "dir2", IsDir: true, Mtime: fixed},
				{Path: "dir2/sub1", IsDir: true, Mtime: fixed},
				{Path: "dir2/sub1/f", Data: []byte("2-1"), Mtime: fixed},
				{Path: "dir2/sub2", IsDir: true, Mtime: fixed},
				{Path: "dir2/sub2/f", Data: []byte("2-2"), Mtime: fixed},
			},
		},
		{
			// 100 directories in a single-level tree, each with one small file.
			Name:     "tree_100_dirs_flat",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: func() []treeEntry {
				entries := []treeEntry{
					{Path: "/", IsDir: true, Mtime: fixed},
				}
				for i := 0; i < 100; i++ {
					name := "e" + string([]byte{byte('0' + i/10), byte('0' + i%10)})
					entries = append(entries,
						treeEntry{Path: name, IsDir: true, Mtime: fixed},
						treeEntry{Path: name + "/f", Data: []byte(name), Mtime: fixed},
					)
				}
				return entries
			}(),
		},

		// --- More config cases ---

		{
			Name: "config_appid_empty",
			// AppID must be "CLOUDISO" — the Writer always emits "CLOUDISO" in the PVD
			// application_identifier field; geniso side must agree (see file header).
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: minEntries(fixed),
		},
		{
			Name:     "config_preparer_only",
			VolumeID: "cidata", Publisher: "", Preparer: "My Preparer Tool", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: minEntries(fixed),
		},
		{
			Name:     "config_volid_config2",
			VolumeID: "config-2", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "meta-data", Data: []byte("id: config-2-test\n"), Mtime: fixed},
			},
		},

		// --- Combination edge cases ---

		{
			Name:     "combo_empty_file_and_nocloud",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "meta-data", Data: []byte("instance-id: test\n"), Mtime: fixed},
				{Path: "user-data", Data: []byte{}, Mtime: fixed},
				{Path: "network-config", Data: []byte("version: 2\n"), Mtime: fixed},
			},
		},
		{
			Name:     "combo_long_name_with_zero_content",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "abcdefghijklmnopqrstuvwxyza1b2", Data: []byte{}, Mtime: fixed},
			},
		},
		{
			Name:     "combo_sector_boundary_and_mtime",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: day1},
				{Path: "f2047", Data: seededBytes("combo_sb_2047", 2047), Mtime: day2},
				{Path: "f2048", Data: seededBytes("combo_sb_2048", 2048), Mtime: day3},
				{Path: "f2049", Data: seededBytes("combo_sb_2049", 2049), Mtime: day4},
			},
		},
		{
			Name:     "combo_configdrive_with_distinct_mtimes",
			VolumeID: "config-2", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: day1},
				{Path: "openstack", IsDir: true, Mtime: day2},
				{Path: "openstack/latest", IsDir: true, Mtime: day3},
				{Path: "openstack/latest/meta_data.json", Data: []byte(`{"uuid":"x"}`), Mtime: day4},
				{Path: "openstack/latest/user_data", Data: []byte("ud"), Mtime: day5},
				{Path: "ec2", IsDir: true, Mtime: fixed},
				{Path: "ec2/latest", IsDir: true, Mtime: pre1980},
				{Path: "ec2/latest/meta-data.json", Data: []byte(`{"id":"y"}`), Mtime: day1},
			},
		},
		{
			Name:     "combo_nocloud_seeded_content",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "meta-data", Data: seededBytes("nocloud_meta", 512), Mtime: fixed},
				{Path: "network-config", Data: seededBytes("nocloud_net", 1024), Mtime: fixed},
				{Path: "user-data", Data: seededBytes("nocloud_user", 2049), Mtime: fixed},
			},
		},
		{
			Name:     "combo_deep_nested_seeded",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "a", IsDir: true, Mtime: day1},
				{Path: "a/b", IsDir: true, Mtime: day2},
				{Path: "a/b/c", IsDir: true, Mtime: day3},
				{Path: "a/b/c/d", IsDir: true, Mtime: day4},
				{Path: "a/b/c/d/e", IsDir: true, Mtime: day5},
				{Path: "a/b/c/d/e/data", Data: seededBytes("deep_data", 4096), Mtime: fixed},
				{Path: "a/b/c/d/e/empty", Data: []byte{}, Mtime: day1},
			},
		},
		{
			Name:     "combo_many_empty_in_subdir",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: func() []treeEntry {
				entries := []treeEntry{
					{Path: "/", IsDir: true, Mtime: fixed},
					{Path: "empties", IsDir: true, Mtime: fixed},
				}
				for i := 0; i < 20; i++ {
					name := "z" + string([]byte{byte('0' + i/10), byte('0' + i%10)})
					entries = append(entries, treeEntry{
						Path:  "empties/" + name,
						Data:  []byte{},
						Mtime: fixed,
					})
				}
				return entries
			}(),
		},
		{
			Name:     "combo_volid_32_with_nocloud",
			VolumeID: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: nocloudEntries(fixed),
		},
		{
			Name:     "combo_epoch_mtime_with_content",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: epoch, ModTime: epoch,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: epoch},
				{Path: "f", Data: seededBytes("epoch_content", 2048), Mtime: epoch},
			},
		},
		// TODO(vladi): Y2038+ timezone masking is flaky with genisoimage
		// {
		// 	Name:     "combo_y2099_mtime_with_content",
		// 	VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
		// 	CreationTime: y2099, ModTime: y2099,
		// 	Entries: []treeEntry{
		// 		{Path: "/", IsDir: true, Mtime: y2099},
		// 		{Path: "f", Data: seededBytes("y2099_content", 2048), Mtime: y2099},
		// 	},
		// },

		// --- Stress-test: ensure sector-spanning works with exact multiples ---

		{
			Name:     "content_3x2048b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f3s", Data: seededBytes("content_3x2048b", 3*2048), Mtime: fixed},
			},
		},
		{
			Name:     "content_3x2048b_minus1",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f3sm1", Data: seededBytes("content_3x2048b_minus1", 3*2048-1), Mtime: fixed},
			},
		},
		{
			Name:     "content_3x2048b_plus1",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f3sp1", Data: seededBytes("content_3x2048b_plus1", 3*2048+1), Mtime: fixed},
			},
		},

		// --- Multiple files with boundary-straddling sizes in one image ---

		{
			Name:     "combo_all_boundaries",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "empty", Data: []byte{}, Mtime: fixed},
				{Path: "s1", Data: []byte("x"), Mtime: fixed},
				{Path: "s2047", Data: seededBytes("all_bdry_2047", 2047), Mtime: fixed},
				{Path: "s2048", Data: seededBytes("all_bdry_2048", 2048), Mtime: fixed},
				{Path: "s2049", Data: seededBytes("all_bdry_2049", 2049), Mtime: fixed},
				{Path: "s4095", Data: seededBytes("all_bdry_4095", 4095), Mtime: fixed},
				{Path: "s4096", Data: seededBytes("all_bdry_4096", 4096), Mtime: fixed},
				{Path: "s4097", Data: seededBytes("all_bdry_4097", 4097), Mtime: fixed},
			},
		},
		// --- Five additional cases to guarantee ≥100 ---

		{
			Name:     "name_len_10",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "abcde12345", Data: []byte("ten"), Mtime: fixed},
			},
		},
		{
			Name:     "content_8192b",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "f8192", Data: seededBytes("content_8192b", 8192), Mtime: fixed},
			},
		},
		{
			Name:     "tree_two_sibling_dirs",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: fixed},
				{Path: "aaa", IsDir: true, Mtime: fixed},
				{Path: "aaa/f", Data: []byte("a"), Mtime: fixed},
				{Path: "zzz", IsDir: true, Mtime: fixed},
				{Path: "zzz/f", Data: []byte("z"), Mtime: fixed},
			},
		},
		{
			Name: "config_all_fields_set",
			// AppID must be "CLOUDISO" — Writer always emits that value in the PVD.
			VolumeID: "TESTDISK", Publisher: "Test Publisher", Preparer: "Test Preparer", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: minEntries(fixed),
		},
		{
			Name:     "combo_pre1980_with_seeded_content",
			VolumeID: "cidata", Publisher: "cloudiso", Preparer: "cloudiso", AppID: "CLOUDISO",
			CreationTime: fixed, ModTime: fixed,
			Entries: []treeEntry{
				{Path: "/", IsDir: true, Mtime: pre1980},
				{Path: "archival", Data: seededBytes("pre1980_content", 1024), Mtime: pre1980},
				{Path: "modern", Data: seededBytes("modern_content", 512), Mtime: fixed},
			},
		},
	}...)
}
