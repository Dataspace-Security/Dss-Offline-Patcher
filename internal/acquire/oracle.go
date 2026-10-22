package acquire

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Oracle JDK downloads (download.oracle.com/java/<feature>/...). Oracle
// serves the current update of a feature release only under /latest/, with
// an unversioned name (jdk-21_windows-x64_bin.msi), and moves an update to
// /archive/ (jdk-21.0.12_windows-x64_bin.msi) once it is superseded. winget
// manifests name one of the two; which one is live depends on the day. So
// the other is tried on HTTP 404. The content is still checked against the
// manifest's SHA-256 whichever URL served it.
//
// An update that is in neither place is not offered under Oracle's No-Fee
// Terms: e.g. Oracle JDK 21 from 21.0.13 is under the OTN license and only
// downloadable with an Oracle account. That is reported as unsupported.

const oracleHost = "https://download.oracle.com/java/"

var (
	oracleArchiveRe = regexp.MustCompile(`^https://download\.oracle\.com/java/(\d{1,3})/archive/jdk-(\d{1,3}(?:\.\d{1,4}){0,5})_([A-Za-z0-9-]+_bin\.[A-Za-z0-9.]{1,12})$`)
	oracleLatestRe  = regexp.MustCompile(`^https://download\.oracle\.com/java/(\d{1,3})/latest/jdk-(\d{1,3})_([A-Za-z0-9-]+_bin\.[A-Za-z0-9.]{1,12})$`)
	oracleVerRe     = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,4}){0,5}$`)
)

// maxOracleSHA256File bounds the published .sha256 file read (64 hex chars
// and perhaps a file name).
const maxOracleSHA256File = 512

// oracleProbeTimeout bounds the .sha256 lookup that orders the candidates.
const oracleProbeTimeout = 15 * time.Second

// isOracleJDK reports whether u is an Oracle JDK download URL this file
// knows the layout of.
func isOracleJDK(u string) bool {
	return oracleArchiveRe.MatchString(u) || oracleLatestRe.MatchString(u)
}

// OracleJDKAlternate returns the other location of the same Oracle JDK file:
// the /latest/ URL for an /archive/ one, the /archive/ URL for a /latest/
// one (only when version, e.g. the winget PackageVersion "21.0.12.0", names
// the update). "" when u is not an Oracle JDK URL or no alternate is known.
func OracleJDKAlternate(u, version string) string {
	if m := oracleArchiveRe.FindStringSubmatch(u); m != nil {
		feature, ver, rest := m[1], m[2], m[3]
		if ver != feature && !strings.HasPrefix(ver, feature+".") {
			return ""
		}
		return oracleHost + feature + "/latest/jdk-" + feature + "_" + rest
	}
	if m := oracleLatestRe.FindStringSubmatch(u); m != nil {
		feature, rest := m[1], m[3]
		if m[2] != feature {
			return ""
		}
		ver := oracleFileVersion(version)
		if ver == "" || ver != feature && !strings.HasPrefix(ver, feature+".") {
			return ""
		}
		return oracleHost + feature + "/archive/jdk-" + ver + "_" + rest
	}
	return ""
}

// oracleFileVersion turns a package version into the one Oracle puts in
// archive file names: trailing ".0" beyond three parts dropped
// ("21.0.12.0" -> "21.0.12", "25.0.4.1" stays), a GA "21.0.0" -> "21".
// "" if version is not dotted digits.
func oracleFileVersion(version string) string {
	v := strings.TrimSpace(version)
	if !oracleVerRe.MatchString(v) {
		return ""
	}
	parts := strings.Split(v, ".")
	for len(parts) > 3 && parts[len(parts)-1] == "0" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 3 && parts[1] == "0" && parts[2] == "0" {
		parts = parts[:1]
	}
	return strings.Join(parts, ".")
}

// oracleCandidates orders the URLs to try for an Oracle JDK file: the one
// whose published SHA-256 (the .sha256 next to the /latest/ file) matches
// the expected hash first, i.e. /latest/ for the current update and
// /archive/ for older ones. If the lookup fails the manifest's URL stays
// first. Either way the other URL follows, for a 404.
func oracleCandidates(ctx context.Context, hc *http.Client, req DownloadRequest) []string {
	alt := OracleJDKAlternate(req.URL, req.Version)
	if alt == "" {
		return []string{req.URL}
	}
	latest, archive := req.URL, alt
	if oracleArchiveRe.MatchString(req.URL) {
		latest, archive = alt, req.URL
	}
	if req.SHA256 == "" {
		return []string{req.URL, alt}
	}
	pub, err := oracleLatestSHA256(ctx, hc, latest+".sha256")
	switch {
	case err != nil:
		return []string{req.URL, alt}
	case pub == req.SHA256:
		return []string{latest, archive}
	default:
		return []string{archive, latest}
	}
}

// oracleLatestSHA256 reads the SHA-256 Oracle publishes for the /latest/
// file (lower-case hex).
func oracleLatestSHA256(ctx context.Context, hc *http.Client, u string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, oracleProbeTimeout)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	r.Header.Set("User-Agent", DefaultUserAgent)
	c := *clientOrDefault(hc)
	c.CheckRedirect = httpsOnlyRedirect
	resp, err := c.Do(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &HTTPStatusError{Method: http.MethodGet, URL: u, Code: resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxOracleSHA256File+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxOracleSHA256File {
		return "", fmt.Errorf("%s: larger than %d bytes", u, maxOracleSHA256File)
	}
	f := strings.Fields(string(b))
	if len(f) == 0 || !hex64Re.MatchString(strings.ToLower(f[0])) {
		return "", fmt.Errorf("%s: no SHA-256", u)
	}
	return strings.ToLower(f[0]), nil
}

// oracleUnavailable is the error when every Oracle location answered 404.
func oracleUnavailable(urls []string) error {
	return unsupported("Oracle no longer offers this JDK update for direct download (not under the No-Fee Terms): HTTP 404 at %s. Oracle keeps only the current update of a JDK release under /latest/ and moves older updates to /archive/; an update in neither place is not available under the Oracle No-Fee Terms (Oracle JDK 21 from 21.0.13, for example, is under the OTN license and needs an Oracle account to download). Import the newest no-fee version, or an OpenJDK build (Eclipse Temurin, Microsoft Build of OpenJDK), instead",
		strings.Join(urls, " and "))
}
