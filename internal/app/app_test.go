package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApp_Lifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	rawCfg := `
server:
  listen: "127.0.0.1:0"
tokens:
  signing_key: "0123456789abcdef0123456789abcdef"
routes:
  - path_prefix: "/dummy"
    target_url: "http://127.0.0.1:9999"
`
	if err := os.WriteFile(cfgPath, []byte(rawCfg), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	application, err := New(Config{
		ConfigPath:    cfgPath,
		WatchEnabled:  false,
		WatchInterval: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to instantiate App: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- application.Run(ctx)
	}()

	// Give it 50ms to bind and serve
	time.Sleep(50 * time.Millisecond)

	// Trigger graceful cancellation
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("app run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("app failed to gracefully shut down in time")
	}
}
