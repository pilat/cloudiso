package cloudiso_test

import (
	"bytes"
	"fmt"
	"time"

	cloudiso "github.com/pilat/cloudiso"
)

// Example_noCloud shows how to build a NoCloud seed ISO with the three
// standard cloud-init files.
func Example_noCloud() {
	fixed := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	w := &cloudiso.Writer{
		VolumeID:  "cidata",
		Publisher: "example",
	}
	_ = w.AddDir("/", fixed)
	_ = w.AddFile("meta-data", []byte("instance-id: iid-1\nlocal-hostname: host1\n"), fixed)
	_ = w.AddFile("user-data", []byte("#cloud-config\n"), fixed)
	_ = w.AddFile("network-config", []byte("version: 2\n"), fixed)

	var buf bytes.Buffer
	if err := w.Write(&buf); err != nil {
		panic(err)
	}

	iso := buf.Bytes()
	// PVD is at sector 16 (byte offset 16*2048). Bytes 1..5 are always "CD001".
	fmt.Println(string(iso[16*2048+1 : 16*2048+6]))
	// Output:
	// CD001
}

// Example_configDrive shows how to build an OpenStack ConfigDrive v2 ISO
// with nested paths under openstack/latest/ and ec2/latest/.
func Example_configDrive() {
	fixed := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	w := &cloudiso.Writer{
		VolumeID:  "config-2",
		Publisher: "example",
	}
	_ = w.AddDir("/", fixed)
	_ = w.AddDir("openstack", fixed)
	_ = w.AddDir("openstack/latest", fixed)
	_ = w.AddDir("ec2", fixed)
	_ = w.AddDir("ec2/latest", fixed)
	_ = w.AddFile("openstack/latest/meta_data.json", []byte(`{"uuid":"abc"}`), fixed)
	_ = w.AddFile("openstack/latest/user_data", []byte("#cloud-config\n"), fixed)
	_ = w.AddFile("ec2/latest/meta-data.json", []byte(`{}`), fixed)

	var buf bytes.Buffer
	if err := w.Write(&buf); err != nil {
		panic(err)
	}

	iso := buf.Bytes()
	// Joliet SVD is at sector 17. Type byte must be 2.
	fmt.Println(iso[17*2048])
	// Output:
	// 2
}
