//go:build pprof

package main

import (
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof on the default mux
	"os"
)

// Profiling is compiled in only with -tags pprof, so a production binary never
// carries it. It listens on loopback, on its own port, apart from the gateway.
//
//	go build -tags pprof ./cmd/gatekey
//	GATEKEY_PPROF=127.0.0.1:6060 ./gatekey -config config.yaml
//	go tool pprof http://127.0.0.1:6060/debug/pprof/heap
func init() {
	if addr := os.Getenv("GATEKEY_PPROF"); addr != "" {
		go func() { _ = http.ListenAndServe(addr, nil) }()
	}
}
