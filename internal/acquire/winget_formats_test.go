package acquire

import "testing"

func TestPublisherID(t *testing.T) {
	for pub, want := range map[string]string{
		"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US": "8wekyb3d8bbwe",
	} {
		if got := PublisherID(pub); got != want {
			t.Errorf("%q: %s, want %s", pub, got, want)
		}
	}
}
