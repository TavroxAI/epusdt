package install

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GMWalletApp/epusdt/config"
	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/data"
	appLog "github.com/GMWalletApp/epusdt/util/log"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func resetInstallTestState(t *testing.T) {
	t.Helper()

	closeInstallDatabases()
	dao.ResetMdbTableInitForTest()
	config.SetConfigPath("")
	viper.Reset()

	t.Cleanup(func() {
		closeInstallDatabases()
		dao.ResetMdbTableInitForTest()
		config.SetConfigPath("")
		viper.Reset()
	})
}

func newInstallTestAPI(envPath string) (*echo.Echo, *installHandler) {
	h := &installHandler{envFilePath: envPath, done: make(chan struct{})}
	e := echo.New()
	e.POST("/install", h.Submit)
	return e, h
}

func submitInstallRequest(t *testing.T, e *echo.Echo, payload string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/install", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return body
}

func assertDoneClosed(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handler did not close done channel within timeout")
	}
}

func changeInstalledAdminPassword(t *testing.T, envPath, newPassword string) {
	t.Helper()

	// §8.1: the operator writes the GMPay keys right after install; config.Init is
	// fail-closed without them, so reopening a freshly installed .env needs them.
	envContent, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read installed env: %v", err)
	}
	envContent = append(bytes.TrimRight(envContent, "\n"),
		"\ngmpay_signing_key=6c1c7d4d6f2a4a3c8f8f1b0f3f9e2a5d4c6b7a8e9f0a1b2c3d4e5f60718293a4\n"+
			"gmpay_reconcile_key=test-reconcile-key-0123456789abcdef\n"...)
	if err := os.WriteFile(envPath, envContent, 0o600); err != nil {
		t.Fatalf("write installed env: %v", err)
	}

	if err := initInstallConfig(envPath); err != nil {
		t.Fatalf("reopen install config: %v", err)
	}
	if err := initInstallDatabases(); err != nil {
		t.Fatalf("reopen install databases: %v", err)
	}
	defer closeInstallDatabases()

	user, err := data.GetAdminUserByUsername("admin")
	if err != nil {
		t.Fatalf("load admin user: %v", err)
	}
	if user.ID == 0 {
		t.Fatal("expected seeded admin user")
	}
	if err := data.UpdateAdminUserPassword(uint64(user.ID), newPassword); err != nil {
		t.Fatalf("change admin password: %v", err)
	}
}

func TestInstallDefaults(t *testing.T) {
	d := InstallDefaults()
	if d.AppName != "epusdt" {
		t.Errorf("AppName = %q, want epusdt", d.AppName)
	}
	if d.HttpBindAddr != "127.0.0.1" {
		t.Errorf("HttpBindAddr = %q, want 127.0.0.1", d.HttpBindAddr)
	}
	if d.HttpBindPort != 8000 {
		t.Errorf("HttpBindPort = %d, want 8000", d.HttpBindPort)
	}
	if d.OrderExpirationTime != 10 {
		t.Errorf("OrderExpirationTime = %d, want 10", d.OrderExpirationTime)
	}
}

func TestWriteEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	req := &InstallRequest{
		AppName:             "myapp",
		AppURI:              "http://1.2.3.4:8000",
		HttpBindAddr:        "0.0.0.0",
		HttpBindPort:        9000,
		RuntimeRootPath:     "./runtime",
		LogSavePath:         "./logs",
		OrderExpirationTime: 15,
		OrderNoticeMaxRetry: 3,
	}
	if err := writeEnvFile(path, req, false); err != nil {
		t.Fatalf("writeEnvFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	content := string(data)

	for _, want := range []string{
		"app_name=myapp",
		"app_uri=http://1.2.3.4:8000",
		"http_listen=0.0.0.0:9000",
		"order_expiration_time=15",
		"order_notice_max_retry=3",
		"db_type=sqlite",
		"install=false",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("env file missing %q\ncontent:\n%s", want, content)
		}
	}
}

func TestInstallAPIDefaults(t *testing.T) {
	h := &installHandler{done: make(chan struct{})}
	e := echo.New()
	e.GET("/install/defaults", h.GetDefaults)

	req := httptest.NewRequest(http.MethodGet, "/install/defaults", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["app_name"] != "epusdt" {
		t.Errorf("app_name = %v, want epusdt", body["app_name"])
	}
	if body["http_bind_addr"] != "127.0.0.1" {
		t.Errorf("http_bind_addr = %v, want 127.0.0.1", body["http_bind_addr"])
	}
	if body["http_bind_port"] != float64(8000) {
		t.Errorf("http_bind_port = %v, want 8000", body["http_bind_port"])
	}
}

func TestInstallServerRootRedirectsToInstall(t *testing.T) {
	dir := t.TempDir()
	wwwRoot := filepath.Join(dir, "www")
	if err := os.MkdirAll(wwwRoot, 0o755); err != nil {
		t.Fatalf("mkdir www root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wwwRoot, "index.html"), []byte("install-ui"), 0o644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}

	e, _ := newInstallServer(filepath.Join(dir, ".env"), wwwRoot)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/install" {
		t.Fatalf("Location = %q, want /install", got)
	}
}

func TestInstallServerServesSPAOnInstallRoute(t *testing.T) {
	dir := t.TempDir()
	wwwRoot := filepath.Join(dir, "www")
	if err := os.MkdirAll(wwwRoot, 0o755); err != nil {
		t.Fatalf("mkdir www root: %v", err)
	}
	const wantBody = "install-ui"
	if err := os.WriteFile(filepath.Join(wwwRoot, "index.html"), []byte(wantBody), 0o644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}

	e, _ := newInstallServer(filepath.Join(dir, ".env"), wwwRoot)

	req := httptest.NewRequest(http.MethodGet, "/install", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); body != wantBody {
		t.Fatalf("body = %q, want %q", body, wantBody)
	}
}

// TestInstallAPISubmitDoesNotReturnInitialPassword covers vuln-0014: the wizard is
// unauthenticated, so returning the generated administrator password to whoever
// submitted the form hands out credentials for the payment gateway. It is printed
// to the local console instead.
func TestInstallAPISubmitDoesNotReturnInitialPassword(t *testing.T) {
	resetInstallTestState(t)

	var printed []string
	restore := captureInitialAdminPassword(t, &printed)
	defer restore()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	e, h := newInstallTestAPI(envPath)

	payload := `{"app_name":"testapp","app_uri":"http://10.0.0.1:8000","http_bind_addr":"0.0.0.0","http_bind_port":8000,"order_expiration_time":10,"order_notice_max_retry":1}`
	rec := submitInstallRequest(t, e, payload)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if got, _ := body["message"].(string); got == "" {
		t.Fatalf("expected success message, got body=%v", body)
	}
	if got, ok := body["init_password"]; ok {
		t.Fatalf("response leaked init_password: %v", got)
	}
	assertDoneClosed(t, h.done)

	if len(printed) != 1 || strings.TrimSpace(printed[0]) == "" {
		t.Fatalf("expected one console password notice, got %v", printed)
	}

	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("env file not written: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "app_uri=http://10.0.0.1:8000") {
		t.Errorf("env file missing app_uri; content:\n%s", content)
	}
	if !strings.Contains(content, "http_listen=0.0.0.0:8000") {
		t.Errorf("env file missing http_listen; content:\n%s", content)
	}
	if !strings.Contains(content, "install=false") {
		t.Errorf("env file missing install=false; content:\n%s", content)
	}
}

// TestInstallAPISubmitRepeatInstallPrintsSamePasswordWhilePlaintextExists keeps the
// recovery path: a repeat install before the operator saved the password still
// prints it, but only to the console.
func TestInstallAPISubmitRepeatInstallPrintsSamePasswordWhilePlaintextExists(t *testing.T) {
	resetInstallTestState(t)

	var printed []string
	restore := captureInitialAdminPassword(t, &printed)
	defer restore()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	payload := `{"app_name":"testapp","app_uri":"http://10.0.0.1:8000","http_bind_addr":"0.0.0.0","http_bind_port":8000,"order_expiration_time":10,"order_notice_max_retry":1}`

	e1, h1 := newInstallTestAPI(envPath)
	rec1 := submitInstallRequest(t, e1, payload)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first install status = %d, want 200; body: %s", rec1.Code, rec1.Body.String())
	}
	assertDoneClosed(t, h1.done)

	e2, h2 := newInstallTestAPI(envPath)
	rec2 := submitInstallRequest(t, e2, payload)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second install status = %d, want 200; body: %s", rec2.Code, rec2.Body.String())
	}
	if got, ok := decodeBody(t, rec2)["init_password"]; ok {
		t.Fatalf("repeat install response leaked init_password: %v", got)
	}
	assertDoneClosed(t, h2.done)

	if len(printed) != 2 {
		t.Fatalf("expected a console password notice for each install, got %v", printed)
	}
	if printed[0] != printed[1] {
		t.Fatalf("repeat install printed a different password: %q vs %q", printed[0], printed[1])
	}
}

func TestInstallAPISubmitRepeatInstallOmitsPasswordAfterPasswordChange(t *testing.T) {
	resetInstallTestState(t)

	var printed []string
	restore := captureInitialAdminPassword(t, &printed)
	defer restore()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	payload := `{"app_name":"testapp","app_uri":"http://10.0.0.1:8000","http_bind_addr":"0.0.0.0","http_bind_port":8000,"order_expiration_time":10,"order_notice_max_retry":1}`

	e1, h1 := newInstallTestAPI(envPath)
	rec1 := submitInstallRequest(t, e1, payload)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first install status = %d, want 200; body: %s", rec1.Code, rec1.Body.String())
	}
	assertDoneClosed(t, h1.done)

	changeInstalledAdminPassword(t, envPath, "new-password-456")

	e2, h2 := newInstallTestAPI(envPath)
	rec2 := submitInstallRequest(t, e2, payload)
	if rec2.Code != http.StatusOK {
		t.Fatalf("repeat install status = %d, want 200; body: %s", rec2.Code, rec2.Body.String())
	}
	body2 := decodeBody(t, rec2)
	if got, ok := body2["init_password"]; ok {
		t.Fatalf("expected init_password to be omitted after password change, got %v", got)
	}
	if got, _ := body2["message"].(string); got == "" {
		t.Fatalf("expected success message, got body=%v", body2)
	}
	assertDoneClosed(t, h2.done)

	// Only the first install printed a password; the retired plaintext is gone.
	if len(printed) != 1 {
		t.Fatalf("expected only the first install to print a password, got %v", printed)
	}
}

// captureInitialAdminPassword swaps the console notice for a recorder.
func captureInitialAdminPassword(t *testing.T, sink *[]string) func() {
	t.Helper()

	original := printInitialAdminPassword
	printInitialAdminPassword = func(password string) {
		*sink = append(*sink, password)
	}
	return func() { printInitialAdminPassword = original }
}

func TestInstallAPISubmitInitFailureKeepsInstallMode(t *testing.T) {
	resetInstallTestState(t)

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	e, h := newInstallTestAPI(envPath)
	// A file where the runtime directory should be makes the database setup fail.
	// The path itself is relative on purpose: absolute paths are rejected by the
	// form validator (the wizard must not write outside the deployment).
	if err := os.WriteFile(filepath.Join(dir, "runtime"), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("prepare blocked runtime path: %v", err)
	}
	payload := `{"app_name":"testapp","app_uri":"http://10.0.0.1:8000","http_bind_addr":"0.0.0.0","http_bind_port":8000,"runtime_root_path":"./runtime","order_expiration_time":10,"order_notice_max_retry":1}`
	rec := submitInstallRequest(t, e, payload)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	select {
	case <-h.done:
		t.Fatal("handler should not close done channel on init failure")
	case <-time.After(100 * time.Millisecond):
	}
	contentBytes, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env after init failure: %v", err)
	}
	content := string(contentBytes)
	if !strings.Contains(content, "install=true") {
		t.Fatalf("expected env to keep install=true after failure; content:\n%s", content)
	}
}

func TestInstallAPISubmitMissingURI(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	e, _ := newInstallTestAPI(envPath)
	rec := submitInstallRequest(t, e, `{"app_name":"x"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if _, err := os.Stat(envPath); err == nil {
		t.Error("env file should not have been written for invalid request")
	}
}

func TestInstallAPISubmitInvalidPort(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	e, _ := newInstallTestAPI(envPath)
	rec := submitInstallRequest(t, e, `{"app_uri":"http://example.com","http_bind_port":99999}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(envPath); err == nil {
		t.Error("env file should not have been written for invalid port")
	}
}

// envKeyCounts counts how many times each key appears in a .env file. It parses
// the file independently of the production parser so the assertions below check
// the written file, not the code that wrote it.
func envKeyCounts(content string) map[string]int {
	counts := make(map[string]int)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		counts[strings.TrimSpace(key)]++
	}
	return counts
}

func readEnvFileString(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

func envBackupPaths(t *testing.T, envPath string) []string {
	t.Helper()

	backups, err := filepath.Glob(envPath + ".bak.*")
	if err != nil {
		t.Fatalf("glob env backups: %v", err)
	}
	return backups
}

func newReinstallRequest() *InstallRequest {
	return &InstallRequest{
		AppName:             "newapp",
		AppURI:              "https://new.example.com",
		HttpBindAddr:        "0.0.0.0",
		HttpBindPort:        9000,
		RuntimeRootPath:     "./runtime",
		LogSavePath:         "./logs",
		OrderExpirationTime: 10,
		OrderNoticeMaxRetry: 8,
	}
}

// TestWriteEnvFileKeepsKeysOutsideTheTemplate covers the real outage: a re-install
// must not drop .env keys the install form does not know about (gmpay_*, mysql_*,
// tg_*), because dropping mysql_* makes the service fail to start and dropping
// gmpay_signing_key makes startup fail closed.
func TestWriteEnvFileKeepsKeysOutsideTheTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	const signingKey = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	oldEnv := `app_name=oldapp
app_uri=http://old.example.com:8000
db_type=mysql
mysql_host=127.0.0.1
mysql_port=3306
mysql_user=epusdt
mysql_passwd=s3cret
tg_bot_token=123:abc
tg_manage=42
gmpay_signing_key=` + signingKey + `
gmpay_reconcile_key=reconcile-key-with-at-least-32-characters
order_expiration_time=10
order_notice_max_retry=8
`
	if err := os.WriteFile(path, []byte(oldEnv), 0o600); err != nil {
		t.Fatalf("write existing env: %v", err)
	}

	if err := writeEnvFile(path, newReinstallRequest(), false); err != nil {
		t.Fatalf("writeEnvFile: %v", err)
	}
	content := readEnvFileString(t, path)

	// Every key of the rewritten file must appear exactly once, including the
	// keys appended from the old file and the two preserved order_* keys.
	for key, n := range envKeyCounts(content) {
		if n != 1 {
			t.Errorf("key %q appears %d times in rewritten env, want exactly once\ncontent:\n%s", key, n, content)
		}
	}
	for _, key := range []string{
		"gmpay_signing_key", "gmpay_reconcile_key", "db_type",
		"mysql_host", "mysql_port", "mysql_user", "mysql_passwd",
		"tg_bot_token", "tg_manage",
		"order_expiration_time", "order_notice_max_retry",
	} {
		if n := envKeyCounts(content)[key]; n != 1 {
			t.Errorf("key %q appears %d times in rewritten env, want exactly once\ncontent:\n%s", key, n, content)
		}
	}
	for _, want := range []string{
		"gmpay_signing_key=" + signingKey,
		"gmpay_reconcile_key=reconcile-key-with-at-least-32-characters",
		"db_type=mysql",
		"mysql_host=127.0.0.1",
		"mysql_port=3306",
		"mysql_user=epusdt",
		"mysql_passwd=s3cret",
		"tg_bot_token=123:abc",
		"tg_manage=42",
		"order_notice_max_retry=8",
		// form-controlled keys still follow the submitted form
		"app_name=newapp",
		"app_uri=https://new.example.com",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("rewritten env missing %q\ncontent:\n%s", want, content)
		}
	}
}

// TestWriteEnvFileModeOnlyGetsTighter covers the permission contract: the rewrite
// and its backup must never end up more permissive than owner-only, and an
// already tight mode (0400) survives a rewrite instead of being normalized to 0600.
func TestWriteEnvFileModeOnlyGetsTighter(t *testing.T) {
	tests := []struct {
		name       string
		oldMode    os.FileMode
		exists     bool
		wantMode   os.FileMode
		wantBackup bool
	}{
		{name: "first install", exists: false, wantMode: 0o600},
		{name: "owner read only is kept", oldMode: 0o400, exists: true, wantMode: 0o400, wantBackup: true},
		{name: "world readable is tightened", oldMode: 0o644, exists: true, wantMode: 0o600, wantBackup: true},
		{name: "group readable is tightened", oldMode: 0o640, exists: true, wantMode: 0o600, wantBackup: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".env")
			const oldContent = "db_type=mysql\ngmpay_signing_key=deadbeef\n"
			if tc.exists {
				if err := os.WriteFile(path, []byte(oldContent), tc.oldMode); err != nil {
					t.Fatalf("write existing env: %v", err)
				}
				if err := os.Chmod(path, tc.oldMode); err != nil {
					t.Fatalf("chmod existing env: %v", err)
				}
			}

			if err := writeEnvFile(path, newReinstallRequest(), false); err != nil {
				t.Fatalf("writeEnvFile: %v", err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat rewritten env: %v", err)
			}
			if got := info.Mode().Perm(); got != tc.wantMode {
				t.Fatalf("env mode = %o, want %o", got, tc.wantMode)
			}

			backups := envBackupPaths(t, path)
			if !tc.wantBackup {
				if len(backups) != 0 {
					t.Fatalf("first install must not create a backup, got %v", backups)
				}
				return
			}
			if len(backups) != 1 {
				t.Fatalf("backup files = %v, want exactly one", backups)
			}
			backupInfo, err := os.Stat(backups[0])
			if err != nil {
				t.Fatalf("stat backup: %v", err)
			}
			if got := backupInfo.Mode().Perm(); got != tc.wantMode {
				t.Errorf("backup mode = %o, want %o (a backup must not be wider than the env)", got, tc.wantMode)
			}
			if got := backupInfo.Mode().Perm(); got&0o077 != 0 {
				t.Errorf("backup mode %o is group/other accessible", got)
			}
			if got := readEnvFileString(t, backups[0]); got != oldContent {
				t.Errorf("backup content = %q, want %q", got, oldContent)
			}
		})
	}
}

// TestWriteEnvFileKeepsOneBackup pins the retention rule: every rewrite adds a
// .env.bak.<ts> copy, so repeated installs must not accumulate readable copies of
// the signing key.
func TestWriteEnvFileKeepsOneBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("gmpay_signing_key=deadbeef\n"), 0o600); err != nil {
		t.Fatalf("write existing env: %v", err)
	}

	for range 3 {
		if err := writeEnvFile(path, newReinstallRequest(), false); err != nil {
			t.Fatalf("writeEnvFile: %v", err)
		}
	}

	backups := envBackupPaths(t, path)
	if len(backups) != 1 {
		t.Fatalf("backup files = %v, want exactly one", backups)
	}
}

// TestWriteEnvFileWarnsWhenEnvValueWins covers the fail-safe for the two keys that
// were removed from formControlledKeys: the .env value is kept, and the ignored
// form value is reported instead of being dropped silently.
func TestWriteEnvFileWarnsWhenEnvValueWins(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	previousSugar := appLog.Sugar
	appLog.Sugar = zap.New(core).Sugar()
	t.Cleanup(func() { appLog.Sugar = previousSugar })

	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("order_notice_max_retry=8\norder_expiration_time=30\n"), 0o600); err != nil {
		t.Fatalf("write existing env: %v", err)
	}

	req := newReinstallRequest()
	req.OrderNoticeMaxRetry = 5
	req.OrderExpirationTime = 10
	if err := writeEnvFile(path, req, false); err != nil {
		t.Fatalf("writeEnvFile: %v", err)
	}

	content := readEnvFileString(t, path)
	counts := envKeyCounts(content)
	if counts["order_notice_max_retry"] != 1 || counts["order_expiration_time"] != 1 {
		t.Fatalf("order keys must appear exactly once, got counts=%v\ncontent:\n%s", counts, content)
	}
	if !strings.Contains(content, "order_notice_max_retry=8") {
		t.Errorf("env value order_notice_max_retry=8 was not preserved\ncontent:\n%s", content)
	}
	if strings.Contains(content, "order_notice_max_retry=5") {
		t.Errorf("form value order_notice_max_retry=5 leaked into the env\ncontent:\n%s", content)
	}
	if !strings.Contains(content, "order_expiration_time=30") {
		t.Errorf("env value order_expiration_time=30 was not preserved\ncontent:\n%s", content)
	}

	entries := logs.All()
	if len(entries) != 2 {
		t.Fatalf("warnings = %v, want exactly two (one per ignored form value)", entries)
	}
	for _, entry := range entries {
		if entry.Level != zapcore.WarnLevel {
			t.Errorf("log level = %v, want warn", entry.Level)
		}
	}
	for _, want := range []struct {
		message string
		parts   []string
	}{
		{
			message: "order_notice_max_retry",
			parts:   []string{"form value order_notice_max_retry=5 ignored", "effective value order_notice_max_retry=8 comes from .env"},
		},
		{
			message: "order_expiration_time",
			parts:   []string{"form value order_expiration_time=10 ignored", "effective value order_expiration_time=30 comes from .env"},
		},
	} {
		found := false
		for _, entry := range entries {
			if !strings.Contains(entry.Message, want.message) {
				continue
			}
			found = true
			for _, part := range want.parts {
				if !strings.Contains(entry.Message, part) {
					t.Errorf("warning %q missing %q", entry.Message, part)
				}
			}
		}
		if !found {
			t.Errorf("no warning mentioned %q; warnings: %v", want.message, entries)
		}
	}
}

// TestWriteEnvFileRefusesDuplicateKey covers the pre-rename self check: a form
// value that would inject a second line for an existing key must abort the write
// and leave the current .env untouched. The submit validator rejects the newline
// before this point, so the assertion here is that no path reaches the sink and
// rewrites the operator's config half-way.
func TestWriteEnvFileRefusesDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	const oldContent = "db_type=mysql\ngmpay_signing_key=deadbeef\n"
	if err := os.WriteFile(path, []byte(oldContent), 0o600); err != nil {
		t.Fatalf("write existing env: %v", err)
	}

	req := newReinstallRequest()
	req.AppName = "evil\napp_name=duplicate"
	if err := writeEnvFile(path, req, false); err == nil {
		t.Fatal("writeEnvFile accepted a form value that duplicates a key")
	}

	if got := readEnvFileString(t, path); got != oldContent {
		t.Fatalf("env file was replaced despite a failed self check, got:\n%s", got)
	}
	if temps, err := filepath.Glob(filepath.Join(dir, ".env.tmp.*")); err != nil {
		t.Fatalf("glob temp files: %v", err)
	} else if len(temps) != 0 {
		t.Fatalf("temp file left behind after failed self check: %v", temps)
	}
}
