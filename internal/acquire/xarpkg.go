package acquire

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// macOS .pkg installers are xar archives: a binary header, a zlib-compressed
// XML table of contents, then a heap with the files. We only need the small
// "Distribution" (product archive) or "PackageInfo" (component package) XML
// to learn which version the installer really contains — vendors' version
// feeds can run ahead of what their fixed download links serve.

type xarTOC struct {
	Files []xarFile `xml:"toc>file"`
}

type xarFile struct {
	Name string `xml:"name"`
	Type string `xml:"type"`
	Data *struct {
		Offset   int64 `xml:"offset"`
		Length   int64 `xml:"length"`
		Size     int64 `xml:"size"`
		Encoding struct {
			Style string `xml:"style,attr"`
		} `xml:"encoding"`
	} `xml:"data"`
	Files []xarFile `xml:"file"`
}

type xarMember struct {
	Name string // path inside the archive, e.g. "Distribution", "Foo.pkg/PackageInfo"
	Data []byte
}

// readXarMembers returns the decoded members whose path satisfies want.
func readXarMembers(path string, want func(name string) bool) ([]xarMember, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var hdr struct {
		Magic     [4]byte
		Size      uint16
		Version   uint16
		TOCComp   uint64
		TOCUncomp uint64
		CkAlg     uint32
	}
	if err := binary.Read(f, binary.BigEndian, &hdr); err != nil {
		return nil, fmt.Errorf("not a pkg (xar) file: %w", err)
	}
	if string(hdr.Magic[:]) != "xar!" || hdr.TOCComp > 16<<20 || hdr.TOCUncomp > 64<<20 {
		return nil, errors.New("not a flat .pkg (xar) installer")
	}
	if _, err := f.Seek(int64(hdr.Size), io.SeekStart); err != nil {
		return nil, err
	}
	zr, err := zlib.NewReader(io.LimitReader(f, int64(hdr.TOCComp)))
	if err != nil {
		return nil, err
	}
	tocXML, err := io.ReadAll(io.LimitReader(zr, int64(hdr.TOCUncomp)))
	if err != nil {
		return nil, err
	}
	var toc xarTOC
	if err := xml.Unmarshal(tocXML, &toc); err != nil {
		return nil, fmt.Errorf("pkg table of contents: %w", err)
	}
	heap := int64(hdr.Size) + int64(hdr.TOCComp)
	var out []xarMember
	var walk func(fs []xarFile, prefix string) error
	walk = func(fs []xarFile, prefix string) error {
		for i := range fs {
			p := prefix + fs[i].Name
			if fs[i].Type == "file" && fs[i].Data != nil && want(p) {
				b, err := readXarData(f, heap, fs[i].Data.Offset, fs[i].Data.Length, fs[i].Data.Size, fs[i].Data.Encoding.Style)
				if err != nil {
					return fmt.Errorf("%s: %w", p, err)
				}
				out = append(out, xarMember{p, b})
			}
			if err := walk(fs[i].Files, p+"/"); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(toc.Files, ""); err != nil {
		return nil, err
	}
	return out, nil
}

func readXarData(f *os.File, heap, off, length, size int64, style string) ([]byte, error) {
	if length > 4<<20 || size > 16<<20 {
		return nil, errors.New("pkg metadata member too large")
	}
	raw := make([]byte, length)
	if _, err := f.ReadAt(raw, heap+off); err != nil {
		return nil, err
	}
	var r io.Reader = bytes.NewReader(raw)
	var err error
	switch {
	case strings.Contains(style, "gzip") && len(raw) > 1 && raw[0] == 0x1f:
		r, err = gzip.NewReader(r)
	case strings.Contains(style, "gzip"):
		r, err = zlib.NewReader(r)
	case strings.Contains(style, "bzip2"):
		r = bzip2.NewReader(r)
	}
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(r, 16<<20))
}

var (
	reBundleVer  = regexp.MustCompile(`<bundle\b[^>]*\sid="([^"]+)"[^>]*\sCFBundleShortVersionString="([^"]+)"`)
	reBundleVer2 = regexp.MustCompile(`<bundle\b[^>]*\sCFBundleShortVersionString="([^"]+)"[^>]*\sid="([^"]+)"`)
	rePkgRef     = regexp.MustCompile(`<pkg-ref\b[^>]*\sid="([^"]+)"[^>]*\sversion="([^"]+)"`)
	rePkgInfo    = regexp.MustCompile(`<pkg-info\b[^>]*>`)
	reAttr       = regexp.MustCompile(`\s(identifier|version)="([^"]*)"`)
)

// PkgVersion returns the version an installer really contains. If bundleID
// is set (an app bundle ID such as "com.google.Chrome", or a package receipt
// ID such as "org.python.Python.PythonFramework-3.15"), that bundle or
// component decides; otherwise the first component package version is used.
// A leading "v" (Node.js "v24.22.0") is dropped.
func PkgVersion(path, bundleID string) (string, error) {
	members, err := readXarMembers(path, func(n string) bool {
		return n == "Distribution" || n == "PackageInfo" || strings.HasSuffix(n, "/PackageInfo")
	})
	if err != nil {
		return "", err
	}
	v, err := pkgVersion(members, bundleID)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	return v, err
}

func pkgVersion(members []xarMember, bundleID string) (string, error) {
	var dist string
	type info struct{ id, version string }
	var infos []info
	for _, m := range members {
		if m.Name == "Distribution" {
			dist = string(m.Data)
			continue
		}
		if tag := rePkgInfo.Find(m.Data); tag != nil {
			var in info
			for _, a := range reAttr.FindAllSubmatch(tag, -1) {
				if string(a[1]) == "identifier" {
					in.id = string(a[2])
				} else {
					in.version = string(a[2])
				}
			}
			if in.version != "" && in.version != "0" {
				infos = append(infos, in)
			}
		}
	}
	if dist == "" && len(infos) == 0 {
		return "", errors.New("pkg has no Distribution or PackageInfo")
	}
	if bundleID != "" {
		for _, m := range reBundleVer.FindAllStringSubmatch(dist, -1) {
			if m[1] == bundleID {
				return m[2], nil
			}
		}
		for _, m := range reBundleVer2.FindAllStringSubmatch(dist, -1) {
			if m[2] == bundleID {
				return m[1], nil
			}
		}
		for _, m := range rePkgRef.FindAllStringSubmatch(dist, -1) {
			if m[1] == bundleID && m[2] != "0" {
				return m[2], nil
			}
		}
		for _, in := range infos {
			if in.id == bundleID {
				return in.version, nil
			}
		}
	}
	if dist == "" {
		return infos[0].version, nil
	}
	for _, m := range rePkgRef.FindAllStringSubmatch(dist, -1) {
		if m[2] != "" && m[2] != "0" && m[2] != "1.0" {
			return m[2], nil
		}
	}
	return "", errors.New("could not find a version in the pkg's Distribution")
}
