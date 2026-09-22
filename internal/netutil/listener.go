package netutil

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"gatekey/internal/logging"
)

// ListenWithFallback attempts to bind to the configured address.
// If the preferred port is already in use (EADDRINUSE), it transparently falls back to
// the next available port (addr + 1, addr + 2, ...) up to maxFallback attempts.
func ListenWithFallback(configuredAddr string, maxFallback int) (net.Listener, string, error) {
	host, portStr, err := net.SplitHostPort(configuredAddr)
	if err != nil {
		// Handle port-only strings like "8080"
		if _, numErr := strconv.Atoi(configuredAddr); numErr == nil {
			host = ""
			portStr = configuredAddr
		} else {
			// Fall back to direct net.Listen for unix sockets or other custom formats
			l, listenErr := net.Listen("tcp", configuredAddr)
			return l, configuredAddr, listenErr
		}
	}

	basePort, err := strconv.Atoi(portStr)
	if err != nil {
		// Non-numeric port (e.g. service name like "http")
		l, listenErr := net.Listen("tcp", configuredAddr)
		return l, configuredAddr, listenErr
	}

	if maxFallback < 1 {
		maxFallback = 1
	}

	for i := 0; i < maxFallback; i++ {
		targetPort := basePort + i
		if targetPort > 65535 {
			break
		}
		addr := net.JoinHostPort(host, strconv.Itoa(targetPort))
		listener, err := net.Listen("tcp", addr)
		if err == nil {
			if i > 0 {
				logging.Warn("configured port was occupied, shifted to a fallback", "configured", basePort, "actual", targetPort, "addr", addr)
			}
			return listener, addr, nil
		}

		// Check if error is specifically address already in use
		isAddrInUse := false
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			var sysErr *os.SyscallError
			if errors.As(opErr.Err, &sysErr) {
				if sysErr.Err == syscall.EADDRINUSE {
					isAddrInUse = true
				}
			}
		}
		if !isAddrInUse && strings.Contains(strings.ToLower(err.Error()), "address already in use") {
			isAddrInUse = true
		}

		if isAddrInUse {
			logging.Debug("port busy, trying the next one", "busy", targetPort, "next", targetPort+1)
			continue
		}

		// For other non-recoverable errors (e.g. permission denied for port < 1024), abort immediately
		return nil, "", fmt.Errorf("failed to bind to %s: %w", addr, err)
	}

	return nil, "", fmt.Errorf("all %d attempted ports starting from %s are occupied", maxFallback, configuredAddr)
}
