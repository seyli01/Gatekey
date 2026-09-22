package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gatekey/internal/app"
)

func TestMain_AppBoot(t *testing.T) {
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

	application, err := app.New(app.Config{
		ConfigPath:   cfgPath,
		WatchEnabled: false,
	})
	if err != nil {
		t.Fatalf("app.New error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- application.Run(ctx)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("app.Run failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("app timed out during graceful shutdown")
	}
}
