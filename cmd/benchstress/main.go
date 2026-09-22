package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gatekey/internal/config"
	"gatekey/internal/proxy"
	"gatekey/internal/token"
)

type Result struct {
	Concurrency int
	TotalReqs   int
	Duration    time.Duration
	RPS         float64
	P50         time.Duration
	P95         time.Duration
	P99         time.Duration
	Max         time.Duration
	Errors      int64
}

func main() {
	fmt.Println("================================================================================")
	fmt.Println(" GATEKEY - STRESS TEST & BENCHMARK DE DÉGRADATION DE PERFORMANCE")
	fmt.Println(" (Conditions : Upstream instantané 0ms, RAM pure, Rate Limiting désactivé)")
	fmt.Println("================================================================================")

	// 1. Upstream ultra-rapide (mock HTTP sans I/O)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"upstream":"instant_ok"}`))
	}))
	defer upstream.Close()

	// 2. Configuration Gatekey
	signingKey, err := token.GenerateKey()
	if err != nil {
		panic(err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:     ":8080",
			AuthHeader: "X-App-Token",
		},
		Tokens: config.TokensConfig{
			SigningKey: string(signingKey),
		},
		Routes: []config.RouteConfig{
			{
				PathPrefix: "/bench",
				TargetURL:  upstream.URL,
				InjectHeaders: map[string]string{
					"Authorization": "Bearer injected-upstream-key",
				},
			},
		},
	}
	_ = cfg.Validate()

	issuer, err := token.NewIssuer(signingKey, cfg.Tokens.ParsedAccessTTL, cfg.Tokens.ParsedRefreshTTL)
	if err != nil {
		panic(err)
	}
	pair, err := issuer.Issue("bench-install", "/bench")
	if err != nil {
		panic(err)
	}
	benchToken := pair.Access

	gw := proxy.NewGateway(cfg, issuer)
	defer gw.Close()

	proxyServer := httptest.NewServer(gw)
	defer proxyServer.Close()

	tiers := []struct {
		concurrency int
		requests    int
	}{
		{concurrency: 10, requests: 10000},
		{concurrency: 25, requests: 20000},
		{concurrency: 50, requests: 30000},
		{concurrency: 100, requests: 50000},
		{concurrency: 200, requests: 50000},
		{concurrency: 400, requests: 50000},
	}

	fmt.Printf("\n%-12s | %-10s | %-12s | %-10s | %-10s | %-10s | %-8s\n",
		"Concurrence", "Requêtes", "Débit (RPS)", "P50", "P95", "P99", "Erreurs")
	fmt.Println("-------------+------------+--------------+------------+------------+------------+---------")

	var results []Result

	for _, tier := range tiers {
		res := runTier(proxyServer.URL, benchToken, tier.concurrency, tier.requests)
		results = append(results, res)
		fmt.Printf("%-12d | %-10d | %-12.0f | %-10v | %-10v | %-10v | %-8d\n",
			res.Concurrency, res.TotalReqs, res.RPS, res.P50, res.P95, res.P99, res.Errors)
	}

	fmt.Println("================================================================================")
	fmt.Println(" ANALYSE DE DÉGRADATION :")
	for i, r := range results {
		status := "Excellente (< 5ms)"
		if r.P99 > 15*time.Millisecond {
			status = "Début de contention / file d'attente TCP"
		} else if r.P99 > 5*time.Millisecond {
			status = "Légère élévation de latence sous forte concurrence"
		}
		fmt.Printf(" -> Concurrence %3d clients : %6.0f req/s | Latence médiane (P50): %v | P99: %v [%s]\n",
			r.Concurrency, r.RPS, r.P50, r.P99, status)
		_ = i
	}
	fmt.Println("================================================================================")
}

func runTier(targetURL, clientToken string, concurrency int, totalRequests int) Result {
	transport := &http.Transport{
		MaxIdleConns:        concurrency * 4,
		MaxIdleConnsPerHost: concurrency * 2,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	reqPerWorker := totalRequests / concurrency
	latencies := make([][]time.Duration, concurrency)

	var errCount int64
	var wg sync.WaitGroup

	start := time.Now()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		workerIdx := i
		go func() {
			defer wg.Done()
			lats := make([]time.Duration, 0, reqPerWorker)

			for j := 0; j < reqPerWorker; j++ {
				t0 := time.Now()
				req, _ := http.NewRequest(http.MethodGet, targetURL+"/bench/test", nil)
				req.Header.Set("X-App-Token", clientToken)

				resp, err := client.Do(req)
				elapsed := time.Since(t0)

				if err != nil {
					atomic.AddInt64(&errCount, 1)
					continue
				}

				if resp.StatusCode != http.StatusOK {
					atomic.AddInt64(&errCount, 1)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				lats = append(lats, elapsed)
			}
			latencies[workerIdx] = lats
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	// Agréger toutes les latences
	allLats := make([]time.Duration, 0, totalRequests)
	for _, l := range latencies {
		allLats = append(allLats, l...)
	}
	sort.Slice(allLats, func(i, j int) bool { return allLats[i] < allLats[j] })

	var p50, p95, p99, maxLat time.Duration
	if len(allLats) > 0 {
		p50 = allLats[len(allLats)*50/100]
		p95 = allLats[len(allLats)*95/100]
		p99 = allLats[len(allLats)*99/100]
		maxLat = allLats[len(allLats)-1]
	}

	rps := float64(len(allLats)) / duration.Seconds()

	return Result{
		Concurrency: concurrency,
		TotalReqs:   len(allLats),
		Duration:    duration,
		RPS:         rps,
		P50:         p50,
		P95:         p95,
		P99:         p99,
		Max:         maxLat,
		Errors:      atomic.LoadInt64(&errCount),
	}
}
