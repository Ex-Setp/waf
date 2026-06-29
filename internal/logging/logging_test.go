package logging

import (
	"bytes"
	"net/url"
	"strings"
	"sync"
	"testing"

	"aegis-waf/internal/config"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	registerMemorySinkOnce sync.Once
	memorySinks            sync.Map
)

func TestNewJSONFormat(t *testing.T) {
	output := t.Name()
	logger := newTestLogger(t, config.LoggingConfig{Level: "info", Format: "json"}, output)
	defer syncLogger(t, logger)

	logger.Info("json message")
	syncLogger(t, logger)

	content := readLog(t, output)
	if !strings.Contains(content, `"level":"info"`) {
		t.Fatalf("expected JSON level field, got %q", content)
	}
	if !strings.Contains(content, `"msg":"json message"`) {
		t.Fatalf("expected JSON message field, got %q", content)
	}
}

func TestNewConsoleFormat(t *testing.T) {
	output := t.Name()
	logger := newTestLogger(t, config.LoggingConfig{Level: "info", Format: "console"}, output)
	defer syncLogger(t, logger)

	logger.Info("console message")
	syncLogger(t, logger)

	content := readLog(t, output)
	if strings.Contains(content, `"msg":"console message"`) {
		t.Fatalf("expected console output, got JSON-looking log %q", content)
	}
	if !strings.Contains(content, "info") || !strings.Contains(content, "console message") {
		t.Fatalf("expected console level and message, got %q", content)
	}
}

func TestNewLevelFiltering(t *testing.T) {
	output := t.Name()
	logger := newTestLogger(t, config.LoggingConfig{Level: "warn", Format: "json"}, output)
	defer syncLogger(t, logger)

	logger.Info("hidden message")
	logger.Warn("visible message")
	syncLogger(t, logger)

	content := readLog(t, output)
	if strings.Contains(content, "hidden message") {
		t.Fatalf("expected info message to be filtered at warn level, got %q", content)
	}
	if !strings.Contains(content, "visible message") {
		t.Fatalf("expected warn message to be logged, got %q", content)
	}
}

func TestNewRejectsInvalidLevel(t *testing.T) {
	_, err := New(config.LoggingConfig{Level: "trace", Format: "json"})
	if err == nil {
		t.Fatal("expected invalid level error")
	}
	if !strings.Contains(err.Error(), "invalid logging level") || !strings.Contains(err.Error(), "trace") {
		t.Fatalf("expected clear invalid level error, got %v", err)
	}
}

func TestNewRejectsInvalidFormat(t *testing.T) {
	_, err := New(config.LoggingConfig{Level: "info", Format: "text"})
	if err == nil {
		t.Fatal("expected invalid format error")
	}
	if !strings.Contains(err.Error(), "invalid logging format") || !strings.Contains(err.Error(), "text") {
		t.Fatalf("expected clear invalid format error, got %v", err)
	}
}

func TestNewSugared(t *testing.T) {
	logger, err := NewSugared(config.LoggingConfig{Level: "debug", Format: "console"})
	if err != nil {
		t.Fatalf("NewSugared returned error: %v", err)
	}
	if logger == nil {
		t.Fatal("expected sugared logger")
	}
}

func newTestLogger(t *testing.T, cfg config.LoggingConfig, outputID string) *zap.Logger {
	t.Helper()
	registerMemorySink(t)

	zapCfg, err := buildConfig(cfg)
	if err != nil {
		t.Fatalf("buildConfig returned error: %v", err)
	}
	zapCfg.OutputPaths = []string{memorySinkURL(outputID)}
	zapCfg.ErrorOutputPaths = []string{memorySinkURL(outputID + "-error")}

	logger, err := zapCfg.Build()
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	return logger
}

func readLog(t *testing.T, outputID string) string {
	t.Helper()

	value, ok := memorySinks.Load(outputID)
	if !ok {
		t.Fatalf("memory sink %q was not created", outputID)
	}

	return value.(*memorySink).String()
}

func syncLogger(t *testing.T, logger *zap.Logger) {
	t.Helper()

	if err := logger.Sync(); err != nil {
		t.Fatalf("sync logger: %v", err)
	}
}

func registerMemorySink(t *testing.T) {
	t.Helper()

	registerMemorySinkOnce.Do(func() {
		err := zap.RegisterSink("memory", func(u *url.URL) (zap.Sink, error) {
			id := strings.TrimPrefix(u.Opaque, "//")
			if id == "" {
				id = u.Host + u.Path
			}

			sink := &memorySink{}
			memorySinks.Store(id, sink)
			return sink, nil
		})
		if err != nil {
			t.Fatalf("register memory sink: %v", err)
		}
	})
}

func memorySinkURL(id string) string {
	return "memory:" + id
}

type memorySink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *memorySink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.buf.Write(p)
}

func (s *memorySink) Sync() error {
	return nil
}

func (s *memorySink) Close() error {
	return nil
}

func (s *memorySink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.buf.String()
}

var _ zapcore.WriteSyncer = (*memorySink)(nil)
