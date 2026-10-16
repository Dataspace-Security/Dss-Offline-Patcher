// fakehsm stands in for an HSM vendor CLI in tests: it signs stdin with the
// key in $FAKEHSM_KEY, or misbehaves when $FAKEHSM_MODE says so.
package main

import (
	"fmt"
	"io"
	"os"

	"offpatch/internal/manifest"
)

func main() {
	msg, _ := io.ReadAll(os.Stdin)
	switch os.Getenv("FAKEHSM_MODE") {
	case "garbage":
		fmt.Println("bm90IGEgc2lnbmF0dXJl")
		return
	case "fail":
		fmt.Fprintln(os.Stderr, "token not present")
		os.Exit(2)
	}
	k, err := manifest.LoadPrivate(os.Getenv("FAKEHSM_KEY"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(manifest.Sign(k, msg))
}
