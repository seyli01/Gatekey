package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// runVerify checks, after Gatekey has shut down, that nothing it served was lost:
// every successful call's tokens in quotas.json, per install and in the route
// total, and every answered call in metrics.json.
func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	stateDir := fs.String("state", "", "Gatekey's state_dir")
	record := fs.String("record", "", "the file the runs appended their tallies to")
	_ = fs.Parse(args)

	var want tally
	f, err := os.Open(*record)
	if err != nil {
		return err
	}
	defer f.Close()
	for sc := bufio.NewScanner(f); sc.Scan(); {
		var t tally
		if err := json.Unmarshal(sc.Bytes(), &t); err != nil {
			return err
		}
		want.Responses += t.Responses
		want.OK += t.OK
	}
	wantTokens := want.OK * (mockPromptTokens + mockCompletionTokens)

	if _, err := os.Stat(filepath.Join(*stateDir, "quotas.json.log")); err == nil {
		fmt.Println("  note: quotas.json.log still exists, Gatekey did not shut down cleanly")
	}
	data, err := os.ReadFile(filepath.Join(*stateDir, "quotas.json"))
	if err != nil {
		return err
	}
	quotaBytes := len(data)
	var quotas map[string]struct {
		TotalTokens uint64 `json:"total_tokens"`
	}
	if err := json.Unmarshal(data, &quotas); err != nil {
		return err
	}
	var perInstall, routeTotal uint64
	installs := 0
	for k, u := range quotas {
		if strings.HasPrefix(k, "*") {
			routeTotal += u.TotalTokens
		} else {
			perInstall += u.TotalTokens
			installs++
		}
	}

	data, err = os.ReadFile(filepath.Join(*stateDir, "metrics.json"))
	if err != nil {
		return err
	}
	var metrics struct {
		Global struct {
			TotalCalls uint64 `json:"total_calls"`
		} `json:"global"`
	}
	if err := json.Unmarshal(data, &metrics); err != nil {
		return err
	}

	check := func(name string, got, want uint64) bool {
		status := "OK"
		if got != want {
			status = fmt.Sprintf("MISMATCH (%+d)", int64(got)-int64(want))
		}
		fmt.Printf("  %-32s got %-12d want %-12d %s\n", name, got, want, status)
		return got == want
	}
	fmt.Println("\n=== Nothing lost?")
	good := check("quota tokens, sum of installs", perInstall, wantTokens)
	good = check("quota tokens, route total", routeTotal, wantTokens) && good
	good = check("metrics calls recorded", metrics.Global.TotalCalls, want.Responses) && good
	fmt.Printf("  %-32s %d\n", "installs in quotas.json", installs)
	fmt.Printf("  %-32s %d KB\n", "quotas.json size", quotaBytes/1024)
	if !good {
		return fmt.Errorf("counts do not match")
	}
	return nil
}
