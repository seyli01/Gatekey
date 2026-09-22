package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Every call reports the same usage, so the generator can tell exactly how many
// tokens Gatekey should have counted.
const (
	mockPromptTokens     = 20
	mockCompletionTokens = 100
)

// runMock serves a fake OpenAI-compatible chat endpoint.
//
// A request whose body asks for "stream":true gets a stream of -chunks events
// spread over -stream, then the usage event and [DONE], like a real provider:
// the connection stays open the whole time, which is what costs Gatekey memory.
// Any other request gets the whole JSON answer at once.
func runMock(args []string) error {
	fs := flag.NewFlagSet("mock", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:9100", "listen address")
	streamFor := fs.Duration("stream", 10*time.Second, "how long a streamed answer lasts")
	chunks := fs.Int("chunks", 100, "content events per streamed answer")
	_ = fs.Parse(args)

	usage := fmt.Sprintf(`{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}`,
		mockPromptTokens, mockCompletionTokens, mockPromptTokens+mockCompletionTokens)
	jsonAnswer := []byte(`{"id":"mock","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}],"usage":` + usage + "}")
	chunk := []byte(`data: {"choices":[{"index":0,"delta":{"content":"lorem "}}]}` + "\n\n")
	final := []byte(`data: {"choices":[],"usage":` + usage + "}\n\ndata: [DONE]\n\n")
	interval := *streamFor / time.Duration(*chunks)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte(`"stream":true`)) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jsonAnswer)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for i := 0; i < *chunks; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			flusher.Flush()
			if i < *chunks-1 {
				select {
				case <-ticker.C:
				case <-r.Context().Done():
					return
				}
			}
		}
		_, _ = w.Write(final)
		flusher.Flush()
	})

	fmt.Printf("mock provider on %s (stream %s, %d chunks)\n", *addr, *streamFor, *chunks)
	return http.ListenAndServe(*addr, handler)
}
