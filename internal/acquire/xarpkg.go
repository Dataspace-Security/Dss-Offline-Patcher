package acquire

import (
	"bytes"
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

func readXarMember(path string, want map[string]bool) (string, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
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
		return "", nil, fmt.Errorf("not a pkg (xar) file: %w", err)
	}
	if string(hdr.Magic[:]) != "xar!" || hdr.TOCComp > 16<<20 || hdr.TOCUncomp > 64<<20 {
		return "", nil, errors.New("not a flat .pkg (xar) installer")
	}
	if _, err := f.Seek(int64(hdr.Size), io.SeekStart); err != nil {
		return "", nil, err
	}
	zr, err := zlib.NewReader(io.LimitReader(f, int64(hdr.TOCComp)))
	if err != nil {
		return "", nil, err
	}
	tocXML, err := io.ReadAll(io.LimitReader(zr, int64(hdr.TOCUncomp)))
	if err != nil {
		return "", nil, err
	}
	var toc xarTOC
	if err := xml.Unmarshal(tocXML, &toc); err != nil {
		return "", nil, fmt.Errorf("pkg table of contents: %w", err)
	}
	heap := int64(hdr.Size) + int64(hdr.TOCComp)
	var find func(fs []xarFile, prefix string) (string, *xarFile)
	find = func(fs []xarFile, prefix string) (string, *xarFile) {
		for i := range fs {
			p := prefix + fs[i].Name
			if fs[i].Type == "file" && want[p] && fs[i].Data != nil {
				return p, &fs[i]
			}
			if n, x := find(fs[i].Files, p+"/"); x != nil {
				return n, x
			}
		}
		return "", nil
	}
	// Prefer the product archive's Distribution over a component PackageInfo.
	for _, name := range []string{"Distribution", "PackageInfo"} {
		if !want[name] {
			continue
		}
		n, x := find(toc.Files, "")
		if x == nil || n != name {
			continue
		}
		d := x.Data
		if d.Length > 4<<20 || d.Size > 16<<20 {
			return "", nil, errors.New("pkg metadata member too large")
		}
		raw := make([]byte, d.Length)
		if _, err := f.ReadAt(raw, heap+d.Offset); err != nil {
			return "", nil, err
		}
		var r io.Reader = bytes.NewReader(raw)
		switch {
		case strings.Contains(d.Encoding.Style, "gzip") && len(raw) > 1 && raw[0] == 0x1f:
			if r, err = gzip.NewReader(r); err != nil {
				return "", nil, err
			}
		case strings.Contains(d.Encoding.Style, "gzip"):
			if r, err = zlib.NewReader(r); err != nil {
				return "", nil, err
			}
		case strings.Contains(d.Encoding.Style, "bzip2"):
			return "", nil, errors.New("bzip2-encoded pkg metadata not supported")
		}
		b, err := io.ReadAll(io.LimitReader(r, 16<<20))
		return name, b, err
	}
	return "", nil, errors.New("pkg has no Distribution or PackageInfo")
}

var (
	reBundleVer  = regexp.MustCompile(`<bundle\b[^>]*\sid="([^"]+)"[^>]*\sCFBundleShortVersionString="([^"]+)"`)
	reBundleVer2 = regexp.MustCompile(`<bundle\b[^>]*\sCFBundleShortVersionString="([^"]+)"[^>]*\sid="([^"]+)"`)
	rePkgRef     = regexp.MustCompile(`<pkg-ref\b[^>]*\sid="([^"]+)"[^>]*\sversion="([^"]+)"`)
	rePkgInfo    = regexp.MustCompile(`<pkg-info\b[^>]*\sversion="([^"]+)"`)
)

// PkgVersion returns the version an installer really contains. If bundleID
// is set (e.g. "com.google.Chrome"), the app bundle with that ID decides;
// otherwise the first component package version is used.
func PkgVersion(path, bundleID string) (string, error) {
	name, x, err := readXarMember(path, map[string]bool{"Distribution": true, "PackageInfo": true})
	if err != nil {
		return "", err
	}
	s := string(x)
	if bundleID != "" {
		for _, m := range reBundleVer.FindAllStringSubmatch(s, -1) {
			if m[1] == bundleID {
				return m[2], nil
			}
		}
		for _, m := range reBundleVer2.FindAllStringSubmatch(s, -1) {
			if m[2] == bundleID {
				return m[1], nil
			}
		}
		for _, m := range rePkgRef.FindAllStringSubmatch(s, -1) {
			if m[1] == bundleID && m[2] != "0" {
				return m[2], nil
			}
		}
	}
	if name == "PackageInfo" {
		if m := rePkgInfo.FindStringSubmatch(s); m != nil {
			return m[1], nil
		}
	}
	for _, m := range rePkgRef.FindAllStringSubmatch(s, -1) {
		if m[2] != "" && m[2] != "0" && m[2] != "1.0" {
			return m[2], nil
		}
	}
	return "", fmt.Errorf("could not find a version in the pkg's %s", name)
}
