# cloudiso

Pure Go library for creating ISO 9660 disk images with Joliet and Rock Ridge extensions. Write-only — does not read existing ISOs. Zero runtime dependencies, no CGo, no external binaries.

[![Go Reference](https://pkg.go.dev/badge/github.com/pilat/cloudiso.svg)](https://pkg.go.dev/github.com/pilat/cloudiso)
[![Go Report Card](https://goreportcard.com/badge/github.com/pilat/cloudiso)](https://goreportcard.com/report/github.com/pilat/cloudiso)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/pilat/cloudiso)](https://github.com/pilat/cloudiso)
[![CI](https://github.com/pilat/cloudiso/actions/workflows/ci.yml/badge.svg)](https://github.com/pilat/cloudiso/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/github/pilat/cloudiso/graph/badge.svg)](https://codecov.io/github/pilat/cloudiso)
![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/pilat/cloudiso?utm_source=oss&utm_medium=github&utm_campaign=pilat%2Fcloudiso&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

## Why this exists

Existing Go ISO libraries are missing pieces: some lack Joliet write support, others have Rock Ridge but no Joliet, some are read-only. The `mkisofs -J -r` combination — both trees, always — is what every real reader expects. This library produces exactly that, aimed at cloud-init seed ISOs (NoCloud `cidata` and OpenStack ConfigDrive v2 `config-2`).

## Install

```
go get github.com/pilat/cloudiso
```

## Usage

### NoCloud seed ISO

```go
fixed := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
w := &cloudiso.Writer{
    VolumeID:  "cidata",
    Publisher: "my-service",
}
_ = w.AddDir("/", fixed)
_ = w.AddFile("meta-data", metaData, fixed)
_ = w.AddFile("user-data", userData, fixed)
_ = w.AddFile("network-config", networkConfig, fixed)

f, _ := os.Create("seed.iso")
defer f.Close()
_ = w.Write(f)
```

### OpenStack ConfigDrive v2

```go
fixed := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
w := &cloudiso.Writer{VolumeID: "config-2", Publisher: "my-service"}
_ = w.AddDir("/", fixed)
_ = w.AddDir("openstack", fixed)
_ = w.AddDir("openstack/latest", fixed)
_ = w.AddDir("ec2", fixed)
_ = w.AddDir("ec2/latest", fixed)
_ = w.AddFile("openstack/latest/meta_data.json", metaJSON, fixed)
_ = w.AddFile("openstack/latest/user_data", userData, fixed)
_ = w.AddFile("ec2/latest/meta-data.json", ec2Meta, fixed)
_ = w.Write(out)
```

Directories are explicit: call `AddDir("/", mtime)` once for root, then `AddDir` for each parent before adding children.
Per-node `mtime` is part of the API so output can byte-match `genisoimage` timestamps for both directory records and RRIP `TF`.

## Scope and non-goals

- No El Torito, no boot catalog, no hybrid MBR — config drives are not boot media.
- No symlinks — cloud-init inputs don't need them.
- No files >4 GiB — sector count fits in a 32-bit field; cidata is kilobytes.
- No mutation API — `Write` is called once; rebuild the tree to change a file.
- No strict Level 1 (UPPERCASE + 8.3) — paths like `meta_data.json` don't round-trip through it.
- No host POSIX metadata — all files get uid=0, gid=0, mode 0444/0555, mirroring `mkisofs -r`.
- Write-only — does not parse existing ISOs.

## Testing

Unit tests run anywhere:

```
go test ./...
```

E2E tests (`e2e_test.go`) build an ISO, mount it inside an Alpine container, diff the tree against input, and compare byte output against a `genisoimage -J -r` reference. They skip automatically if Docker is not available, so `go test ./...` is always safe to run locally.

## License

MIT — see [LICENSE](LICENSE).

## References

- ECMA-119 (ISO 9660) — the primary on-disk structure spec
- Joliet Specification (Microsoft, 1995) — UCS-2 SVD layout and escape sequences
- RRIP 1.12 (IEEE P1282) — Rock Ridge Interchange Protocol field definitions
- SUSP 1.12 (IEEE P1281) — System Use Sharing Protocol framing
