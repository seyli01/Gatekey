package netutil

import (
	"fmt"
	"net"
	"testing"
)

func TestListenWithFallback(t *testing.T) {
	// Find an available port dynamically first
	dummyL1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate dummy listener: %v", err)
	}
	basePort := dummyL1.Addr().(*net.TCPAddr).Port

	// Pre-occupy basePort+1 as well
	dummyL2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", basePort+1))
	if err != nil {
		_ = dummyL1.Close()
		t.Skipf("port %d not free to test consecutive fallback: %v", basePort+1, err)
	}
	defer dummyL1.Close()
	defer dummyL2.Close()

	// 1. When basePort and basePort+1 are occupied, ListenWithFallback should jump to basePort+2
	targetAddr := fmt.Sprintf("127.0.0.1:%d", basePort)
	listener, actualAddr, err := ListenWithFallback(targetAddr, 5)
	if err != nil {
		t.Fatalf("expected ListenWithFallback to succeed on fallback, got err: %v", err)
	}
	defer listener.Close()

	expectedPort := basePort + 2
	expectedAddr := fmt.Sprintf("127.0.0.1:%d", expectedPort)
	if actualAddr != expectedAddr {
		t.Errorf("expected fallback address %s, got %s", expectedAddr, actualAddr)
	}

	// 2. Max fallback exhaustion test
	_, _, err = ListenWithFallback(targetAddr, 2)
	if err == nil {
		t.Errorf("expected error when maxFallback=2 is exhausted, got nil")
	}
}
