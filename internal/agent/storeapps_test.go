package agent

import "testing"

func TestParseStoreApps(t *testing.T) {
	out := []byte(`[{"id":"Microsoft.WindowsTerminal_8wekyb3d8bbwe","name":"Microsoft.WindowsTerminal","version":"1.21.1.0"},
{"id":"Microsoft.WindowsTerminal_8wekyb3d8bbwe","name":"Microsoft.WindowsTerminal","version":"1.22.0.0"},
{"id":"","name":"x","version":"1"}]`)
	got := parseStoreApps(out)
	if len(got) != 1 || got[0].Kind != "appx" || got[0].Version != "1.22.0.0" || got[0].Source != "msstore" {
		t.Fatalf("got %+v", got)
	}
	if parseStoreApps([]byte("not json")) != nil {
		t.Fatal("bad output should give no items")
	}
}
