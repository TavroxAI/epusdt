package install

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestInstallAPISubmitRejectsEnvInjection reproduces the reported install-form
// injection: a newline inside app_uri appended attacker-chosen .env keys
// (gmpay_signing_key / gmpay_reconcile_key), silently replacing the instance's
// notification signing root and its order-lookup key.
func TestInstallAPISubmitRejectsEnvInjection(t *testing.T) {
	resetInstallTestState(t)
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	e, h := newInstallTestAPI(envPath)

	payload, err := json.Marshal(map[string]interface{}{
		"app_name":          "epusdt",
		"app_uri":           "https://pay.example.com\ngmpay_signing_key=" + strings.Repeat("aa", 32) + "\ngmpay_reconcile_key=" + strings.Repeat("A", 40),
		"http_bind_addr":    "127.0.0.1",
		"http_bind_port":    8000,
		"log_save_path":     "./logs",
		"runtime_root_path": "./runtime",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	rec := submitInstallRequest(t, e, string(payload))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("install status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	message, _ := body["error"].(string)
	if !strings.Contains(message, "app_uri") {
		t.Fatalf("error = %q, want it to name app_uri", message)
	}
	if _, err := os.Stat(envPath); !os.IsNotExist(err) {
		t.Fatalf(".env was written despite a rejected submission (err=%v)", err)
	}
	assertInstallNotDone(t, h.done)
}

// TestInstallAPISubmitRejectsLineBreaksInEveryInterpolatedField walks the whole
// class, not just app_uri: every value the template substitutes must be a single
// line, otherwise the same injection is available through another field.
func TestInstallAPISubmitRejectsLineBreaksInEveryInterpolatedField(t *testing.T) {
	fields := []string{"app_name", "http_bind_addr", "runtime_root_path", "log_save_path"}
	payloads := map[string]string{
		"CRLF": "value\r\ngmpay_signing_key=" + strings.Repeat("aa", 32),
		"NUL":  "value\x00gmpay_signing_key=" + strings.Repeat("aa", 32),
	}

	for _, field := range fields {
		for name, value := range payloads {
			t.Run(field+"/"+name, func(t *testing.T) {
				resetInstallTestState(t)
				dir := t.TempDir()
				envPath := filepath.Join(dir, ".env")
				e, h := newInstallTestAPI(envPath)

				payload, err := json.Marshal(map[string]interface{}{
					"app_name":          "epusdt",
					"app_uri":           "https://pay.example.com",
					"http_bind_addr":    "127.0.0.1",
					"http_bind_port":    8000,
					"log_save_path":     "./logs",
					"runtime_root_path": "./runtime",
					field:               value,
				})
				if err != nil {
					t.Fatalf("marshal payload: %v", err)
				}

				rec := submitInstallRequest(t, e, string(payload))
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("install status = %d, want 400; body=%s", rec.Code, rec.Body.String())
				}
				if message, _ := decodeBody(t, rec)["error"].(string); !strings.Contains(message, field) {
					t.Fatalf("error = %q, want it to name %s", message, field)
				}
				if _, err := os.Stat(envPath); !os.IsNotExist(err) {
					t.Fatalf(".env was written despite a rejected submission (err=%v)", err)
				}
				assertInstallNotDone(t, h.done)
			})
		}
	}
}

// TestWriteEnvFileRefusesUnexpectedKey covers the second layer: keys outside the
// template's own key set and the keys preserved from the previous file are
// refused even if they somehow reach the rendered document, because the expected
// key set is derived from the template text rather than from the document itself.
func TestWriteEnvFileRefusesUnexpectedKey(t *testing.T) {
	const allowedContent = "app_name=epusdt\napp_uri=https://pay.example.com\n"
	expected := []string{"app_name", "app_uri"}
	allowed := []string{"app_name", "app_uri"}

	if err := verifyEnvContent(allowedContent, expected, allowed); err != nil {
		t.Fatalf("verifyEnvContent rejected a legitimate document: %v", err)
	}

	injected := allowedContent + "gmpay_signing_key=" + strings.Repeat("aa", 32) + "\n"
	err := verifyEnvContent(injected, expected, allowed)
	if err == nil {
		t.Fatal("verifyEnvContent accepted a key outside the allowed set")
	}
	if !strings.Contains(err.Error(), "unexpected key") {
		t.Fatalf("verifyEnvContent error = %v, want an unexpected-key error", err)
	}

	duplicated := allowedContent + "app_name=evil\n"
	err = verifyEnvContent(duplicated, expected, allowed)
	if err == nil || !strings.Contains(err.Error(), "2 times") {
		t.Fatalf("verifyEnvContent error = %v, want a duplicate-key error", err)
	}
}

// TestEnvTemplateKeysMatchRenderedOutput keeps the derived key list honest: the
// keys extracted from the template text must be exactly the keys a render
// produces, otherwise the allow-list and the document could drift apart.
func TestEnvTemplateKeysMatchRenderedOutput(t *testing.T) {
	var buf bytes.Buffer
	req := newReinstallRequest()
	if err := envTemplate.Execute(&buf, envTemplateData{InstallRequest: req, InstallValue: "false"}); err != nil {
		t.Fatalf("render template: %v", err)
	}

	rendered := envTemplateKeyNames(buf.String())
	if !slices.Equal(rendered, envTemplateKeys) {
		t.Fatalf("rendered keys = %v, template keys = %v", rendered, envTemplateKeys)
	}
}

// assertInstallNotDone fails when a rejected submission still finalized the
// install (which would let the caller race the operator into a completed setup).
func assertInstallNotDone(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
		t.Fatal("install completed despite a rejected submission")
	default:
	}
}
