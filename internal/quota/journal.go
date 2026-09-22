package quota

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// journal persists usage counters as a snapshot plus an append-only log.
//
// Rewriting every counter on every flush made the cost of a flush grow with the
// number of installations rather than with traffic: at 100,000 installs a single
// request meant re-encoding 20 MB. The journal instead appends one line per
// counter that changed since the last flush, and folds the log back into the
// snapshot only once the log has grown as large as the snapshot itself -- so
// each change is written a bounded number of times, whatever the install count.
//
// Both files stay plain JSON, readable and repairable by hand:
//
//	quotas.json      {"<route>:<install>": {...}, ...}   same shape as before
//	quotas.json.log  {"k":"<route>:<install>","u":{...}}  one counter per line
//
// Every line carries the counter's full value rather than a delta, and loading
// keeps whichever state of a counter is the later one (see supersedes). Replaying
// a line twice therefore changes nothing, which is what makes every crash window
// safe: a torn final line, a retried append, or a log that outlived the
// compaction that should have removed it.
type journal struct {
	snapPath string
	logPath  string

	snapBytes   int64     // size of the snapshot as last written or loaded
	logBytes    int64     // bytes appended since the last compaction
	lastCompact time.Time // when the snapshot was last rewritten

	// tornTail is set when the log may end mid-line: after a crash, or after an
	// append that failed partway. The next append then starts on a fresh line,
	// so the fragment stays a line of its own that load skips, instead of
	// swallowing the first counter written after it.
	tornTail bool
}

// compactMinBytes keeps a small log from being compacted over and over: below
// this, replaying the log at startup costs less than rewriting the snapshot.
const compactMinBytes = 1 << 20

// compactMaxAge bounds how long lapsed counters can linger. Pruning happens at
// compaction, and a quiet install may take a long time to fill the log.
const compactMaxAge = 24 * time.Hour

type logLine struct {
	Key   string     `json:"k"`
	Usage TokenUsage `json:"u"`
}

func newJournal(snapPath string) *journal {
	return &journal{snapPath: snapPath, logPath: snapPath + ".log", lastCompact: time.Now()}
}

// needsCompaction reports whether the log should be folded into the snapshot.
// Waiting until the log matches the snapshot's size is what bounds the total
// write cost: a counter is rewritten by a compaction at most once for every time
// it was appended.
func (j *journal) needsCompaction(now time.Time) bool {
	if j.logBytes == 0 {
		return false
	}
	return j.logBytes >= max(compactMinBytes, j.snapBytes) || now.Sub(j.lastCompact) >= compactMaxAge
}

// load reads the snapshot, then replays the log over it.
func (j *journal) load() map[string]*TokenUsage {
	usages := make(map[string]*TokenUsage)

	if data, err := os.ReadFile(j.snapPath); err == nil {
		j.snapBytes = int64(len(data))
		var saved map[string]*TokenUsage
		if json.Unmarshal(data, &saved) == nil {
			for k, u := range saved {
				if u != nil {
					usages[k] = u
				}
			}
		}
	}

	f, err := os.Open(j.logPath)
	if err != nil {
		return usages
	}
	defer f.Close()

	if fi, err := f.Stat(); err == nil && fi.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, fi.Size()-1); err != nil || last[0] != '\n' {
			j.tornTail = true
		}
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		j.logBytes += int64(len(scanner.Bytes())) + 1
		var line logLine
		// A line that does not parse is the torn tail of an append interrupted by
		// a crash. The counter's previous state is still on disk, earlier in the
		// log or in the snapshot, so skipping it loses at most that one flush.
		if json.Unmarshal(scanner.Bytes(), &line) != nil || line.Key == "" {
			continue
		}
		if cur, ok := usages[line.Key]; !ok || supersedes(*cur, line.Usage) {
			u := line.Usage
			usages[line.Key] = &u
		}
	}
	return usages
}

// supersedes reports whether b is a later state of a counter than a.
//
// Within one accounting window a counter only ever grows -- Record refuses a
// zero-token call -- so the larger one is the later one. Across windows the
// later window wins, and because a window resets the counter to zero, "larger"
// alone would get that wrong. When the granularity itself changed (a route moved
// from monthly to daily), nothing orders the two, and the one read last wins.
func supersedes(a, b TokenUsage) bool {
	if a.Period != b.Period {
		if len(a.Period) == len(b.Period) {
			return b.Period > a.Period
		}
		return true
	}
	if a.TotalTokens != b.TotalTokens {
		return b.TotalTokens > a.TotalTokens
	}
	return b.TotalCostUSD >= a.TotalCostUSD
}

// append writes one line per changed counter and waits for the disk to have it.
func (j *journal) append(lines []logLine) error {
	var buf bytes.Buffer
	if j.tornTail {
		buf.WriteByte('\n')
	}
	enc := json.NewEncoder(&buf) // Encode terminates each value with '\n'
	for i := range lines {
		if err := enc.Encode(&lines[i]); err != nil {
			return err
		}
	}

	if err := ensureDir(j.logPath); err != nil {
		return err
	}
	// The keys name installations, which is enough to enumerate a tenant's users:
	// owner-only, like the snapshot.
	f, err := os.OpenFile(j.logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(buf.Bytes())
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		// Some of the bytes may have landed. Assume the worst about where the
		// file now ends; an extra empty line costs nothing.
		j.tornTail = true
		return err
	}
	j.logBytes += int64(buf.Len())
	j.tornTail = false
	return nil
}

// compact replaces the snapshot with snap and discards the log.
//
// The order is what keeps a crash harmless at every step: the new snapshot is
// durable before it replaces the old one, and the old one is replaced before the
// log goes. A crash in between leaves a log whose lines are older than the
// snapshot, and supersedes discards them on the next load.
func (j *journal) compact(snap map[string]TokenUsage, now time.Time) error {
	if err := ensureDir(j.snapPath); err != nil {
		return err
	}
	tmp := j.snapPath + ".tmp"
	size, err := writeSnapshot(tmp, snap)
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, j.snapPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(j.snapPath)

	if err := os.Remove(j.logPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	j.snapBytes, j.logBytes, j.lastCompact, j.tornTail = size, 0, now, false
	return nil
}

// writeSnapshot streams the map one entry at a time rather than marshalling it
// whole, so a large snapshot never needs a second copy of itself in memory.
func writeSnapshot(path string, snap map[string]TokenUsage) (int64, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	w := bufio.NewWriterSize(f, 256*1024)
	cw := &countingWriter{w: w}

	werr := func() error {
		if _, err := cw.Write([]byte{'{'}); err != nil {
			return err
		}
		first := true
		for k, u := range snap {
			if !first {
				if _, err := cw.Write([]byte{','}); err != nil {
					return err
				}
			}
			first = false
			key, err := json.Marshal(k)
			if err != nil {
				return err
			}
			val, err := json.Marshal(u)
			if err != nil {
				return err
			}
			if _, err := cw.Write(key); err != nil {
				return err
			}
			if _, err := cw.Write([]byte{':'}); err != nil {
				return err
			}
			if _, err := cw.Write(val); err != nil {
				return err
			}
		}
		if _, err := cw.Write([]byte("}\n")); err != nil {
			return err
		}
		return w.Flush()
	}()
	// Sync before the rename: without it a power cut can leave the renamed file
	// empty, because the rename reached the disk before the data did.
	serr := f.Sync()
	cerr := f.Close()
	return cw.n, errors.Join(werr, serr, cerr)
}

type countingWriter struct {
	w *bufio.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func ensureDir(path string) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		return os.MkdirAll(dir, 0o755)
	}
	return nil
}

// syncDir makes a rename durable. Best effort: some filesystems refuse to sync a
// directory, and the data itself is already on disk by then.
func syncDir(path string) {
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
