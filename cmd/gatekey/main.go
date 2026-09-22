package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"gatekey/internal/app"
	"gatekey/internal/config"
	"gatekey/internal/logging"
	"gatekey/internal/token"
)

func main() {
	// Subcommands are matched before flag parsing so "gatekey issue -install=x"
	// keeps the plain "gatekey -config=..." server invocation untouched.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "genkey":
			runGenKey()
			return
		case "issue":
			runIssue(os.Args[2:])
			return
		}
	}
	runServer()
}

// runServer starts the reverse proxy, which is what a bare "gatekey" does.
func runServer() {
	var configPath string
	var watchEnabled bool
	var watchInterval time.Duration

	flag.StringVar(&configPath, "config", "config.yaml", "Path to YAML configuration file")
	flag.BoolVar(&watchEnabled, "watch", true, "Automatically watch and reload configuration on file change")
	flag.DurationVar(&watchInterval, "watch-interval", 2*time.Second, "Polling interval for configuration watcher")
	flag.Parse()

	configPath = resolveConfigPath(configPath)

	application, err := app.New(app.Config{
		ConfigPath:    configPath,
		WatchEnabled:  watchEnabled,
		WatchInterval: watchInterval,
	})
	if err != nil {
		fatal(err)
	}

	if err := application.Run(context.Background()); err != nil {
		fatal(err)
	}
}

// runGenKey prints a fresh signing key for tokens.signing_key.
//
// It deliberately touches no file: the key belongs in a secrets store or an
// environment variable, and writing it into the YAML for the user would invite
// committing it.
func runGenKey() {
	key, err := token.GenerateKey()
	if err != nil {
		fatal(err)
	}

	fmt.Println(base64.RawURLEncoding.EncodeToString(key))
	fmt.Fprintln(os.Stderr, "\nStore this as GATEKEY_SIGNING_KEY and reference it from config.yaml:")
	fmt.Fprintln(os.Stderr, "  tokens:")
	fmt.Fprintln(os.Stderr, "    signing_key: \"${GATEKEY_SIGNING_KEY}\"")
	fmt.Fprintln(os.Stderr, "\nRotating it invalidates every token already issued.")
}

// runIssue enrols one installation and prints its token pair.
//
// The pair is minted through app.BuildIssuer, the same constructor the running
// server uses, so a token this command prints cannot be one the server refuses.
func runIssue(args []string) {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "Path to YAML configuration file")
	installID := fs.String("install", "", "Identifier for this installation (keys quotas and survives refresh)")
	route := fs.String("route", "", "Route prefix the token may reach, e.g. /openai")
	ttl := fs.Duration("ttl", 0, "Access-token lifetime, overriding tokens.access_ttl. Use a long value for a caller that cannot refresh, such as a cron job (e.g. 87600h)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if *installID == "" || *route == "" {
		fmt.Fprintln(os.Stderr, "usage: gatekey issue -install <id> -route </prefix> [-ttl 87600h] [-config config.yaml]")
		os.Exit(2)
	}

	cfg, err := config.Load(resolveConfigPath(*configPath))
	if err != nil {
		fatal(err)
	}

	issuer, err := app.BuildIssuer(cfg)
	if err != nil {
		fatal(err)
	}
	accessTTL := *ttl
	if accessTTL <= 0 {
		accessTTL = issuer.AccessTTL()
	}
	pair, err := issuer.IssueWithTTL(*installID, *route, accessTTL)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("install_id        %s\n", *installID)
	fmt.Printf("route             %s\n\n", *route)
	fmt.Printf("access_token      %s\n", pair.Access)
	fmt.Printf("  expires         %s\n\n", pair.AccessExpiresAt.UTC().Format(time.RFC3339))
	fmt.Printf("refresh_token     %s\n", pair.Refresh)
	fmt.Printf("  expires         %s\n", pair.RefreshExpiresAt.UTC().Format(time.RFC3339))

	fmt.Fprintln(os.Stderr, "\nShip the refresh token in the OS keychain and exchange it at POST /-/refresh;")
	fmt.Fprintln(os.Stderr, "send the access token in the auth header on every proxied request.")
}

// fatal reports an unrecoverable start-up error and stops.
func fatal(err error) {
	logging.Error("fatal", "err", err)
	os.Exit(1)
}

// resolveConfigPath lets GATEKEY_CONFIG override the default without overriding
// an explicit -config flag.
func resolveConfigPath(path string) string {
	if envPath := os.Getenv("GATEKEY_CONFIG"); envPath != "" && path == "config.yaml" {
		return envPath
	}
	return path
}
