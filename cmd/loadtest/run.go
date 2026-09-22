package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gatekey/internal/config"
	"gatekey/internal/token"
)

// sample is one request as the generator saw it.
type sample struct {
	ttfb, total time.Duration
}

// tally is what Gatekey must have recorded for the runs aimed at it, appended to
// the -record file so verify can check it once Gatekey has shut down.
type tally struct {
	Responses uint64 `json:"responses"` // every HTTP answer, errors included: metrics count them all
	OK        uint64 `json:"ok"`        // complete successful calls: quotas count these
}

func runLoad(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	target := fs.String("target", "", "URL to load, e.g. http://127.0.0.1:8095/mock/v1/chat/completions")
	cfgPath := fs.String("config", "", "Gatekey configuration, to sign tokens (omit for a direct baseline)")
	route := fs.String("route", "/mock", "route prefix the tokens are issued for")
	mode := fs.String("mode", "stream", "stream | short | attack")
	conc := fs.Int("conc", 100, "concurrent workers")
	installs := fs.Int("installs", 10000, "distinct installs, used round robin")
	duration := fs.Duration("duration", 30*time.Second, "how long workers keep starting requests")
	ramp := fs.Duration("ramp", 5*time.Second, "spread worker start-up over this long")
	legit := fs.Int("legit", 20, "attack mode: workers sending valid requests alongside the attack")
	pid := fs.Int("pid", 0, "Gatekey's PID, to sample its memory, CPU and open files")
	record := fs.String("record", "", "append what Gatekey should have counted to this file")
	label := fs.String("label", "", "name printed with the results")
	_ = fs.Parse(args)
	if *target == "" {
		return fmt.Errorf("-target is required")
	}

	tokens, err := issueTokens(*cfgPath, *route, *installs)
	if err != nil {
		return err
	}

	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		MaxIdleConns:        *conc + *legit + 16,
		MaxIdleConnsPerHost: *conc + *legit + 16,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute}
	defer transport.CloseIdleConnections()

	body := `{"model":"mock","messages":[{"role":"user","content":"hi"}]}`
	if *mode == "stream" {
		body = `{"model":"mock","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	}

	var (
		next      atomic.Uint64 // round-robin install cursor
		responses atomic.Uint64
		ok        atomic.Uint64
		errMu     sync.Mutex
		errs      = map[string]int{}
	)
	noteErr := func(e string) {
		errMu.Lock()
		errs[e]++
		errMu.Unlock()
	}

	// One call. forged sends a token Gatekey must refuse.
	call := func(forged bool) (sample, bool) {
		req, _ := http.NewRequest(http.MethodPost, *target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		switch {
		case forged:
			req.Header.Set("X-App-Token", "gk1.eyJmb3JnZWQiOnRydWV9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		case len(tokens) > 0:
			req.Header.Set("X-App-Token", tokens[next.Add(1)%uint64(len(tokens))])
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			noteErr(shortErr(err))
			return sample{}, false
		}
		defer resp.Body.Close()
		responses.Add(1)

		// Time to the first body byte: for a stream, the first event.
		br := bufio.NewReader(resp.Body)
		_, peekErr := br.Peek(1)
		ttfb := time.Since(start)
		rest, readErr := io.ReadAll(br)
		total := time.Since(start)

		if forged {
			if resp.StatusCode != http.StatusUnauthorized {
				noteErr(fmt.Sprintf("forged token got HTTP %d", resp.StatusCode))
			}
			return sample{ttfb, total}, true
		}
		if resp.StatusCode != http.StatusOK {
			noteErr(fmt.Sprintf("HTTP %d", resp.StatusCode))
			return sample{}, false
		}
		if peekErr != nil || readErr != nil {
			noteErr("body read failed")
			return sample{}, false
		}
		if *mode == "stream" && !strings.Contains(string(rest), "[DONE]") {
			noteErr("stream ended early")
			return sample{}, false
		}
		ok.Add(1)
		return sample{ttfb, total}, true
	}

	sampler := startSampler(*pid)

	deadline := time.Now().Add(*duration)
	var wg sync.WaitGroup
	results := make([][]sample, *conc)
	attackResults := make([][]sample, 0)
	worker := func(slot *[]sample, forged bool, delay time.Duration) {
		defer wg.Done()
		time.Sleep(delay)
		for time.Now().Before(deadline) {
			if s, good := call(forged); good {
				*slot = append(*slot, s)
			}
		}
	}

	begin := time.Now()
	switch *mode {
	case "attack":
		// conc attackers with forged tokens, legit honest workers next to them:
		// what matters is how the honest ones fare.
		attackResults = make([][]sample, *conc)
		results = make([][]sample, *legit)
		for i := 0; i < *conc; i++ {
			wg.Add(1)
			go worker(&attackResults[i], true, rampDelay(i, *conc, *ramp))
		}
		for i := 0; i < *legit; i++ {
			wg.Add(1)
			go worker(&results[i], false, 0)
		}
	default:
		for i := 0; i < *conc; i++ {
			wg.Add(1)
			go worker(&results[i], false, rampDelay(i, *conc, *ramp))
		}
	}
	wg.Wait()
	elapsed := time.Since(begin)
	usage := sampler.stop()

	all := flatten(results)
	fmt.Printf("\n=== %s  (mode %s, %d workers, %s)\n", *label, *mode, *conc, elapsed.Round(time.Second))
	fmt.Printf("  successful calls   %d  (%.0f/s)\n", len(all), float64(len(all))/elapsed.Seconds())
	printLatency("  first byte", all, func(s sample) time.Duration { return s.ttfb })
	printLatency("  whole call", all, func(s sample) time.Duration { return s.total })
	if *mode == "attack" {
		forged := flatten(attackResults)
		fmt.Printf("  forged calls       %d refused (%.0f/s)\n", len(forged), float64(len(forged))/elapsed.Seconds())
		printLatency("  refusal", forged, func(s sample) time.Duration { return s.total })
	}
	if len(errs) == 0 {
		fmt.Println("  errors             none")
	}
	for e, n := range errs {
		fmt.Printf("  error              %dx %s\n", n, e)
	}
	usage.print()

	if *record != "" {
		f, err := os.OpenFile(*record, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		return json.NewEncoder(f).Encode(tally{Responses: responses.Load(), OK: ok.Load()})
	}
	return nil
}

func issueTokens(cfgPath, route string, n int) ([]string, error) {
	if cfgPath == "" {
		return nil, nil
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	issuer, err := token.NewIssuer([]byte(cfg.Tokens.SigningKey), time.Hour, time.Hour)
	if err != nil {
		return nil, err
	}
	tokens := make([]string, n)
	for i := range tokens {
		pair, err := issuer.Issue(fmt.Sprintf("load-%06d", i), route)
		if err != nil {
			return nil, err
		}
		tokens[i] = pair.Access
	}
	return tokens, nil
}

// rampDelay spreads start-up: 20,000 connections opened in the same instant
// measure the kernel's SYN backlog, not Gatekey.
func rampDelay(i, n int, ramp time.Duration) time.Duration {
	if n <= 1 {
		return 0
	}
	return ramp * time.Duration(i) / time.Duration(n)
}

func flatten(parts [][]sample) []sample {
	var all []sample
	for _, p := range parts {
		all = append(all, p...)
	}
	return all
}

func printLatency(name string, all []sample, pick func(sample) time.Duration) {
	if len(all) == 0 {
		fmt.Printf("%-20s -\n", name)
		return
	}
	d := make([]time.Duration, len(all))
	for i, s := range all {
		d[i] = pick(s)
	}
	sort.Slice(d, func(a, b int) bool { return d[a] < d[b] })
	q := func(p float64) time.Duration { return d[int(p*float64(len(d)-1))] }
	fmt.Printf("%-20s p50 %-10s p95 %-10s p99 %-10s max %s\n", name, fmtDur(q(.50)), fmtDur(q(.95)), fmtDur(q(.99)), fmtDur(d[len(d)-1]))
}

func fmtDur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

func shortErr(err error) string {
	s := err.Error()
	for _, known := range []string{"connection refused", "connection reset", "too many open files", "timeout", "EOF", "cannot assign requested address"} {
		if strings.Contains(s, known) {
			return known
		}
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// procSampler reads Gatekey's resource use from /proc once a second.
type procSampler struct {
	pid    int
	cancel context.CancelFunc
	done   chan procUsage
}

type procUsage struct {
	pid                  int
	peakRSSKB, lastRSSKB int64
	peakFDs, peakThreads int
	avgCPU, peakCPU      float64 // percent of one core
	samples              int
}

func startSampler(pid int) *procSampler {
	ctx, cancel := context.WithCancel(context.Background())
	s := &procSampler{pid: pid, cancel: cancel, done: make(chan procUsage, 1)}
	go func() {
		u := procUsage{pid: pid}
		if pid == 0 {
			<-ctx.Done()
			s.done <- u
			return
		}
		const hz = 100 // USER_HZ on Linux
		first, _ := cpuTicks(pid)
		prev, prevAt := first, time.Now()
		start := prevAt
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				if now, err := cpuTicks(pid); err == nil {
					if secs := time.Since(start).Seconds(); secs > 0 {
						u.avgCPU = float64(now-first) / hz / secs * 100
					}
				}
				s.done <- u
				return
			case now := <-tick.C:
				if t, err := cpuTicks(pid); err == nil {
					cpu := float64(t-prev) / hz / now.Sub(prevAt).Seconds() * 100
					u.peakCPU = max(u.peakCPU, cpu)
					prev, prevAt = t, now
				}
				rss, threads := statusOf(pid)
				u.lastRSSKB = rss
				u.peakRSSKB = max(u.peakRSSKB, rss)
				u.peakThreads = max(u.peakThreads, threads)
				if fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); err == nil {
					u.peakFDs = max(u.peakFDs, len(fds))
				}
				u.samples++
			}
		}
	}()
	return s
}

func (s *procSampler) stop() procUsage {
	s.cancel()
	return <-s.done
}

func (u procUsage) print() {
	if u.pid == 0 {
		return
	}
	fmt.Printf("  gatekey RSS        peak %.0f MB, end %.0f MB\n", float64(u.peakRSSKB)/1024, float64(u.lastRSSKB)/1024)
	fmt.Printf("  gatekey CPU        avg %.0f%%, peak %.0f%% (100%% = one core of 12)\n", u.avgCPU, u.peakCPU)
	fmt.Printf("  gatekey open files peak %d, OS threads peak %d\n", u.peakFDs, u.peakThreads)
}

func cpuTicks(pid int) (int64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// The command name may contain spaces; fields are counted after its ')'.
	fields := strings.Fields(string(data[strings.LastIndexByte(string(data), ')')+1:]))
	var utime, stime int64
	fmt.Sscan(fields[11], &utime)
	fmt.Sscan(fields[12], &stime)
	return utime + stime, nil
}

func statusOf(pid int) (rssKB int64, threads int) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, found := strings.CutPrefix(line, "VmRSS:"); found {
			fmt.Sscan(v, &rssKB)
		}
		if v, found := strings.CutPrefix(line, "Threads:"); found {
			fmt.Sscan(v, &threads)
		}
	}
	return rssKB, threads
}
