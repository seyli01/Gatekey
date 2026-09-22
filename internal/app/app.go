package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gatekey/internal/config"
	"gatekey/internal/credential"
	"gatekey/internal/logging"
	"gatekey/internal/metrics"
	"gatekey/internal/netutil"
	"gatekey/internal/proxy"
	"gatekey/internal/routes"
	"gatekey/internal/token"
)

// Config holds the startup parameters for the Gatekey application.
type Config struct {
	ConfigPath    string
	WatchEnabled  bool
	WatchInterval time.Duration
}

// App represents the initialized Gatekey service and runtime supervisor.
type App struct {
	cfg        Config
	cfgMgr     *config.Manager
	metricsCol *metrics.Collector
	gateway    *proxy.Gateway
	router     http.Handler
}

// New creates and wires all components for the Gatekey application.
func New(cfg Config) (*App, error) {
	// The configuration is read before anything is logged: it carries the level
	// and format, and emitting first would put text lines at the head of what an
	// operator asked to be a JSON stream. A failure here still reports through the
	// package default, since there is no configured logger to use yet.
	cfgMgr, err := config.NewManager(cfg.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	initialCfg := cfgMgr.Get()

	if err := logging.Configure(initialCfg.Server.LogLevel, initialCfg.Server.LogFormat, os.Stderr); err != nil {
		return nil, fmt.Errorf("failed to configure logging: %w", err)
	}

	logging.Info("starting Gatekey", "config", cfg.ConfigPath)

	// Initialize asynchronous metrics collector and disk history flusher
	metricsCol := metrics.NewCollector(initialCfg.Server.StatePath("metrics.json"), 60*time.Second)

	// The token issuer is the only credential check on the request path.
	issuer, err := BuildIssuer(initialCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token issuer: %w", err)
	}
	logging.Info("token issuer ready",
		"access_ttl", issuer.AccessTTL().String(),
		"refresh_ttl", issuer.RefreshTTL().String(),
		"revoked_installs", len(initialCfg.Tokens.Denylist))

	// Rotated refresh tokens are persisted beside the other runtime state.
	credStore, err := credential.NewFileStore(initialCfg.Server.StatePath("credentials.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to open the credential store: %w", err)
	}

	// Initialize Reverse Proxy Gateway
	gateway := proxy.NewGateway(initialCfg, issuer)
	gateway.SetCredentialStore(credStore)
	gateway.AttachConfigManager(cfgMgr)
	gateway.SetMetricsCollector(metricsCol)

	// Rebuild the issuer on every reload so a rotated signing key, a changed TTL
	// or a new denylist entry applies without a restart. A failure here keeps the
	// previous issuer rather than leaving the gateway with none, which would lock
	// out every legitimate client at once.
	cfgMgr.OnReload(func(_, newCfg *config.Config) {
		if err := logging.Configure(newCfg.Server.LogLevel, newCfg.Server.LogFormat, os.Stderr); err != nil {
			logging.Error("keeping the previous logging setup", "err", err)
		}

		newIssuer, err := BuildIssuer(newCfg)
		if err != nil {
			logging.Error("keeping the previous token issuer, the new configuration is unusable", "err", err)
			return
		}
		gateway.SetIssuer(newIssuer)
	})

	// Build application HTTP router
	router := routes.NewRouter(routes.Options{
		Gateway:   gateway,
		ConfigMgr: cfgMgr,
		Collector: metricsCol,
	})

	return &App{
		cfg:        cfg,
		cfgMgr:     cfgMgr,
		metricsCol: metricsCol,
		gateway:    gateway,
		router:     router,
	}, nil
}

// BuildIssuer constructs the token issuer described by a configuration. It is
// exported so the "gatekey issue" command mints tokens through exactly the same
// path the server verifies them on.
func BuildIssuer(cfg *config.Config) (*token.Issuer, error) {
	issuer, err := token.NewIssuer([]byte(cfg.Tokens.SigningKey), cfg.Tokens.ParsedAccessTTL, cfg.Tokens.ParsedRefreshTTL)
	if err != nil {
		return nil, err
	}
	issuer.SetDenylist(token.NewDenylist(cfg.Tokens.Denylist))
	return issuer, nil
}

// Run executes the application server, signal listeners, and graceful shutdown.
func (a *App) Run(ctx context.Context) error {
	defer a.metricsCol.Close()
	defer a.gateway.Close()

	appCtx, cancelApp := context.WithCancel(ctx)
	defer cancelApp()

	// Start auto-watcher if enabled
	if a.cfg.WatchEnabled {
		logging.Info("configuration watcher enabled", "interval", a.cfg.WatchInterval.String())
		a.cfgMgr.StartWatcher(appCtx, a.cfg.WatchInterval, func(cfg *config.Config) {
			logging.Info("configuration reloaded from disk", "routes", len(cfg.Routes))
		}, func(err error) {
			logging.Error("reload failed, keeping the active configuration", "err", err)
		})
	}

	initialCfg := a.cfgMgr.Get()
	server := &http.Server{
		Addr:              initialCfg.Server.Listen,
		Handler:           a.router,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Channel for graceful shutdown triggers
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Channel for SIGHUP hot reload
	reloadSig := make(chan os.Signal, 1)
	signal.Notify(reloadSig, syscall.SIGHUP)

	// SIGHUP listener goroutine
	go func() {
		for range reloadSig {
			logging.Info("SIGHUP received, reloading configuration")
			newCfg, err := a.cfgMgr.Reload()
			if err != nil {
				logging.Error("SIGHUP reload failed, keeping the active configuration", "err", err)
			} else {
				logging.Info("configuration reloaded via SIGHUP", "routes", len(newCfg.Routes))
			}
		}
	}()

	// Bind to port with automatic fallback
	listener, actualAddr, err := netutil.ListenWithFallback(initialCfg.Server.Listen, 20)
	if err != nil {
		return fmt.Errorf("failed to bind address: %w", err)
	}
	defer listener.Close()

	// Start server in background
	go func() {
		logging.Info("listening", "addr", actualAddr, "auth_header", initialCfg.Server.AuthHeader)
		logging.Info("routes configured", "count", len(initialCfg.Routes))
		for _, r := range initialCfg.Routes {
			logging.Info("route", "prefix", r.PathPrefix, "target", r.TargetURL, "strip_prefix", r.ShouldStripPrefix())
		}

		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logging.Error("server error", "err", err)
		}
	}()

	// Wait for shutdown trigger
	select {
	case sig := <-stop:
		logging.Info("signal received, shutting down gracefully", "signal", sig)
	case <-ctx.Done():
		logging.Info("context cancelled, shutting down gracefully")
	}

	// Allow pending streams up to 15 seconds to finish
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logging.Error("graceful shutdown failed, forcing exit", "err", err)
		_ = server.Close()
	}

	logging.Info("server stopped cleanly")
	return nil
}
