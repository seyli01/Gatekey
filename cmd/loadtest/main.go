// Command loadtest measures Gatekey under load, as three separate processes:
//
//	loadtest mock   -- a fake LLM provider: streams OpenAI-style SSE, or answers
//	                   JSON at once, and always reports token usage
//	gatekey         -- the real binary, real configuration, quotas and metrics on
//	loadtest run    -- the load generator, one distinct install per worker, which
//	                   also samples the Gatekey process from /proc
//	loadtest verify -- after Gatekey has shut down, checks that every token and
//	                   every call it served reached quotas.json and metrics.json
//
// A real provider is never the target: it would cost money, rate-limit the test
// within seconds, and measure its own speed rather than Gatekey's.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: loadtest mock|run|verify [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "mock":
		err = runMock(os.Args[2:])
	case "run":
		err = runLoad(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadtest:", err)
		os.Exit(1)
	}
}
