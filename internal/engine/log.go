package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Log levels.
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

var levelRank = map[string]int{LevelDebug: 0, LevelInfo: 1, LevelWarn: 2, LevelError: 3}

type LogEntry struct {
	Seq   uint64 `json:"seq"`
	Time  int64  `json:"time"` // unix milliseconds
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

const (
	logMax      = 2000
	logFileSize = 5 << 20 // the file is rotated to <name>.1 beyond this
)

// logBuffer keeps the most recent log lines for the UI and, when configured,
// appends them to a file.
type logBuffer struct {
	mu      sync.Mutex
	seq     uint64
	entries []LogEntry
	sink    func(LogEntry)

	file     *os.File
	filePath string
	fileSize int64
	fileRank int
}

func (e *Engine) logf(level, format string, args ...any) {
	le := LogEntry{Time: time.Now().UnixMilli(), Level: level, Msg: fmt.Sprintf(format, args...)}
	b := &e.log
	b.mu.Lock()
	b.seq++
	le.Seq = b.seq
	if len(b.entries) >= logMax {
		b.entries = append(b.entries[:0], b.entries[logMax/4:]...)
	}
	b.entries = append(b.entries, le)
	if b.file != nil && levelRank[level] >= b.fileRank {
		b.writeFile(le)
	}
	sink := b.sink
	b.mu.Unlock()
	if sink != nil {
		sink(le)
	}
}

// writeFile appends one line. mu must be held.
func (b *logBuffer) writeFile(le LogEntry) {
	line := fmt.Sprintf("%s %-5s %s\n",
		time.UnixMilli(le.Time).Format("2006-01-02 15:04:05.000"), strings.ToUpper(le.Level), le.Msg)
	if b.fileSize+int64(len(line)) > logFileSize {
		_ = b.file.Close()
		_ = os.Remove(b.filePath + ".1")
		_ = os.Rename(b.filePath, b.filePath+".1")
		f, err := os.OpenFile(b.filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			b.file = nil
			return
		}
		b.file, b.fileSize = f, 0
	}
	n, _ := b.file.WriteString(line)
	b.fileSize += int64(n)
}

// setLogFile switches the log file; an empty path closes it.
func (e *Engine) setLogFile(path, level string) error {
	b := &e.log
	b.mu.Lock()
	defer b.mu.Unlock()
	rank, ok := levelRank[level]
	if !ok {
		rank = levelRank[LevelInfo]
	}
	b.fileRank = rank
	if path == b.filePath && (path == "" || b.file != nil) {
		return nil
	}
	if b.file != nil {
		_ = b.file.Close()
		b.file = nil
	}
	b.filePath = path
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Connection logs name hosts and programs: owner-only, like the profile.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	b.file, b.fileSize = f, st.Size()
	return nil
}

// SetLogSink installs a callback that receives every log line, e.g. to
// print it on the console.
func (e *Engine) SetLogSink(f func(LogEntry)) {
	e.log.mu.Lock()
	e.log.sink = f
	e.log.mu.Unlock()
}

// Logs returns the buffered lines with a sequence number greater than after.
func (e *Engine) Logs(after uint64) []LogEntry {
	b := &e.log
	b.mu.Lock()
	defer b.mu.Unlock()
	i := len(b.entries)
	for i > 0 && b.entries[i-1].Seq > after {
		i--
	}
	return append([]LogEntry(nil), b.entries[i:]...)
}
