package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jayekwere/hardened-container-supply-chain/internal/policy"
)

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: policy manifests|scan [flags]")
		return 2
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	file := f.String("file", "", "rendered manifests or scan JSON")
	exceptions := f.String("exceptions", "security/exceptions.json", "exception ledger")
	imageID := f.String("image-id", "", "expected image config digest")
	subject := f.String("subject", "", "exact artifact digest (manifest digest for a release)")
	if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 {
		return 2
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var failures []string
	switch args[0] {
	case "manifests":
		docs, err := policy.DecodeManifests(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		failures = policy.Manifests(docs)
	case "scan":
		var report policy.Report
		if err := json.Unmarshal(raw, &report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		eraw, err := os.ReadFile(*exceptions)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		e, err := policy.DecodeExceptions(eraw)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		var accepted []string
		failures, accepted = policy.Scan(report, e, *imageID, *subject, ".", time.Now().UTC())
		for _, a := range accepted {
			fmt.Println(a)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown policy mode")
		return 2
	}
	for _, failure := range failures {
		fmt.Println("DENY", failure)
	}
	if len(failures) > 0 {
		return 1
	}
	fmt.Println("PASS", args[0])
	return 0
}
