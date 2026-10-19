package agent

import (
	"net/http"
	"slices"
	"testing"

	"offpatch/internal/pki"
)

// Agents offer ALPN dss-agent/1 so the server answers them with the internal
// certificate even on a name browsers get a public certificate for. They
// must offer http/1.1 as well: the server never negotiates dss-agent/1
// itself, and a client offering only protocols the server lacks is refused.
func TestAgentOffersALPN(t *testing.T) {
	hc, err := httpClient("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	p := hc.Transport.(*http.Transport).TLSClientConfig.NextProtos
	if len(p) == 0 || p[0] != pki.AgentALPN || !slices.Contains(p, "http/1.1") || slices.Contains(p, "h2") {
		t.Fatalf("NextProtos = %v, want [%s http/1.1]", p, pki.AgentALPN)
	}
}
