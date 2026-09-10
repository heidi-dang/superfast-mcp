package mcpx

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestTelemetryLogsOnlySanitizedRequestMetadata(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := requestTelemetry(next)
	req := httptest.NewRequest(http.MethodPost, "/mcp?code=sensitive-code&state=sensitive-state", nil)
	req.Header.Set("Authorization", "Bearer sensitive-bearer")
	req.Header.Set("Cf-Access-Jwt-Assertion", "sensitive-assertion")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	got := logs.String()
	for _, want := range []string{`"msg":"http request"`, `"method":"POST"`, `"path":"/mcp"`, `"status":418`} {
		if !strings.Contains(got, want) {
			t.Fatalf("telemetry missing %s: %s", want, got)
		}
	}
	for _, forbidden := range []string{"sensitive-code", "sensitive-state", "sensitive-bearer", "sensitive-assertion", "Authorization", "Cf-Access-Jwt-Assertion"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("telemetry leaked %q: %s", forbidden, got)
		}
	}
}

func TestRequestTelemetryPreservesResponseControllerFlush(t *testing.T) {
	flushed := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatalf("Flush failed through telemetry wrapper: %v", err)
		}
		flushed = true
	})
	handler := requestTelemetry(next)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if !flushed || !rec.Flushed {
		t.Fatalf("flush was not propagated: handler=%v recorder=%v", flushed, rec.Flushed)
	}
}

func TestHTTPHandlerUsesRequestTelemetryWhenJSONLoggingEnabled(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	cfg := testConfig(t)
	cfg.LogJSON = true
	handler, err := NewHTTPHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/health?token=sensitive-query", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	got := logs.String()
	if !strings.Contains(got, `"msg":"http request"`) || !strings.Contains(got, `"path":"/health"`) || !strings.Contains(got, `"status":200`) {
		t.Fatalf("handler telemetry missing request metadata: %s", got)
	}
	if strings.Contains(got, "sensitive-query") {
		t.Fatalf("handler telemetry leaked query: %s", got)
	}
}
