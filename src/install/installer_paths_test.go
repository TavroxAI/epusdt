package install

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallAPISubmitRejectsNonRelativeRuntimePaths covers vuln-0022: the wizard
// writes these values into .env unchanged, so an absolute path (or a Windows
// drive/UNC path) lets an unauthenticated caller place the runtime database and
// the daily log file at a location they control — including a remote SMB share.
func TestInstallAPISubmitRejectsNonRelativeRuntimePaths(t *testing.T) {
	cases := []struct {
		field string
		value string
	}{
		{"runtime_root_path", "/var/lib/epusdt"},
		{"runtime_root_path", "/tmp"},
		{"runtime_root_path", `C:\epusdt\runtime`},
		{"runtime_root_path", `c:/epusdt/runtime`},
		{"runtime_root_path", `\\attacker.example\share\runtime`},
		{"runtime_root_path", "//attacker.example/share/runtime"},
		{"runtime_root_path", "../escape"},
		{"runtime_root_path", "runtime/../../escape"},
		{"log_save_path", "/var/log/epusdt"},
		{"log_save_path", `D:\logs`},
		{"log_save_path", `\\attacker.example\share\logs`},
		{"log_save_path", "../logs"},
	}

	for _, tc := range cases {
		t.Run(tc.field+"="+tc.value, func(t *testing.T) {
			resetInstallTestState(t)
			dir := t.TempDir()
			envPath := filepath.Join(dir, ".env")
			e, h := newInstallTestAPI(envPath)

			payload := map[string]interface{}{
				"app_name":          "epusdt",
				"app_uri":           "https://pay.example.com",
				"http_bind_addr":    "127.0.0.1",
				"http_bind_port":    8000,
				"runtime_root_path": "./runtime",
				"log_save_path":     "./logs",
			}
			payload[tc.field] = tc.value
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}

			rec := submitInstallRequest(t, e, string(body))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if message, _ := decodeBody(t, rec)["error"].(string); !strings.Contains(message, tc.field) {
				t.Fatalf("error = %q, want it to name %s", message, tc.field)
			}
			if _, err := os.Stat(envPath); !os.IsNotExist(err) {
				t.Fatalf(".env was written despite a rejected path (err=%v)", err)
			}
			assertInstallNotDone(t, h.done)
		})
	}
}

// TestInstallAPISubmitAcceptsRelativeRuntimePaths keeps the guard from breaking
// the documented defaults.
func TestInstallAPISubmitAcceptsRelativeRuntimePaths(t *testing.T) {
	for _, value := range []string{"./runtime", "runtime", "runtime/epusdt", "./logs/nested"} {
		t.Run(value, func(t *testing.T) {
			req := &InstallRequest{RuntimeRootPath: value, LogSavePath: value}
			if err := validateInstallFields(req); err != nil {
				t.Fatalf("validateInstallFields(%q) = %v, want accepted", value, err)
			}
		})
	}
}

// TestInstallListenAddrDefaultsToLoopback covers the exposure half of vuln-0014:
// the unauthenticated wizard must not listen on every interface by default.
func TestInstallListenAddrDefaultsToLoopback(t *testing.T) {
	t.Setenv(InstallAddrEnvVar, "")
	if got := ListenAddr(); got != DefaultInstallAddr {
		t.Fatalf("ListenAddr() = %q, want %q", got, DefaultInstallAddr)
	}
	if DefaultInstallAddr != "127.0.0.1:8000" {
		t.Fatalf("DefaultInstallAddr = %q, want a loopback bind", DefaultInstallAddr)
	}

	// Container deployments opt in explicitly.
	t.Setenv(InstallAddrEnvVar, ":8000")
	if got := ListenAddr(); got != ":8000" {
		t.Fatalf("ListenAddr() with opt-in = %q, want :8000", got)
	}
}
