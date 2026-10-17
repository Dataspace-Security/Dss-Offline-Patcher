package store

import (
	"testing"

	"offpatch/internal/manifest"
)

// A .pkg update for an app the Mac App Store installed is never offered:
// Apple's installer refuses it, and the App Store updates the app itself.
func TestAppStoreAppsNotOffered(t *testing.T) {
	p := Package{Kind: "pkg", PackageName: "com.microsoft.Word", Version: "16.115",
		Applicability: manifest.Applicability{OS: "macos", Arch: "any"}}
	e := Endpoint{OS: "macos", Arch: "arm64"}
	direct := []InventoryItem{{Kind: "app", ID: "com.microsoft.Word", Version: "16.114"}}
	store := []InventoryItem{{Kind: "app", ID: "com.microsoft.Word", Version: "16.114", Source: "appstore"}}
	if ok, _, _ := needs(p, e, direct, nil); !ok {
		t.Fatal("directly installed older Word should need the update")
	}
	if ok, _, _ := needs(p, e, store, nil); ok {
		t.Fatal("App Store Word must not be offered a .pkg update")
	}
	if !appStoreManaged(store, p) || appStoreManaged(direct, p) {
		t.Fatal("appStoreManaged")
	}
}
