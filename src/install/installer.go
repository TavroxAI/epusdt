// Package install provides a first-run setup REST API.
//
// When the .env config file is absent (or has install=true) the HTTP start
// command calls RunInstallServer, which listens on the same address the main
// server will eventually use (default :8000) and mounts two JSON endpoints
// consumed by the frontend install UI:
//
//	GET  /api/install/defaults  — default field values for the form
//	POST /api/install           — validate + initialize install state, then shut down
//
// The HTTP listen address is submitted as two separate fields (http_bind_addr
// and http_bind_port) and combined internally as "ADDR:PORT" before writing
// the http_listen key in .env.  This makes the form easier for users who only
// want to change the port without touching the bind address.
//
// Once install state is initialized and the .env is finalized with
// install=false, the install server stops and normal bootstrap proceeds on the
// same port without a restart.
package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/GMWalletApp/epusdt/config"
	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/data"
	luluHttp "github.com/GMWalletApp/epusdt/util/http"
	appLog "github.com/GMWalletApp/epusdt/util/log"
	"github.com/gookit/color"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
)

// DefaultInstallAddr is the listen address used by the install API.
//
// It is loopback only: the wizard has no authentication by design (nobody can log
// in before an account exists), so it must not be reachable from the network by
// default. Deployments that complete setup over the network — containers
// publishing port 8000, for example — must opt in explicitly with
// EPUSDT_INSTALL_ADDR (the image does).
const DefaultInstallAddr = "127.0.0.1:8000"

// InstallAddrEnvVar lets an operator publish the first-run wizard beyond loopback.
const InstallAddrEnvVar = "EPUSDT_INSTALL_ADDR"

// ListenAddr returns the address the install wizard should bind: the explicit
// opt-in from the environment when present, otherwise loopback.
func ListenAddr() string {
	if addr := strings.TrimSpace(os.Getenv(InstallAddrEnvVar)); addr != "" {
		return addr
	}
	return DefaultInstallAddr
}

// InstallRequest is the payload submitted by the install form.
// All fields are optional except AppURI; omitted fields fall back to InstallDefaults().
type InstallRequest struct {
	// Application display name (default: epusdt)
	AppName string `json:"app_name" form:"app_name" example:"epusdt"`
	// Public base URL of the service, e.g. https://pay.example.com (required)
	AppURI string `json:"app_uri" form:"app_uri" example:"https://pay.example.com"`
	// Bind address for the HTTP server (default: 127.0.0.1)
	HttpBindAddr string `json:"http_bind_addr" form:"http_bind_addr" example:"127.0.0.1"`
	// Bind port for the HTTP server (default: 8000)
	HttpBindPort int `json:"http_bind_port" form:"http_bind_port" example:"8000"`
	// Runtime directory for SQLite DB and temp files (default: ./runtime)
	RuntimeRootPath string `json:"runtime_root_path" form:"runtime_root_path" example:"./runtime"`
	// Directory for application log files (default: ./logs)
	LogSavePath string `json:"log_save_path" form:"log_save_path" example:"./logs"`
	// Minutes before an unpaid order expires (default: 10)
	OrderExpirationTime int `json:"order_expiration_time" form:"order_expiration_time" example:"10"`
	// Maximum webhook retry attempts (default: 1)
	OrderNoticeMaxRetry int `json:"order_notice_max_retry" form:"order_notice_max_retry" example:"1"`
}

// InstallSubmitResponse is returned when the install request succeeds.
type InstallSubmitResponse struct {
	// Completion message for the install request.
	Message string `json:"message" example:"install complete, starting server…"`
	// Initial admin password, returned only while the plaintext is still available.
	InitPassword string `json:"init_password,omitempty" example:"a1b2c3d4e5f6"`
}

// InstallDefaults returns sensible default values for the install form.
func InstallDefaults() InstallRequest {
	return InstallRequest{
		AppName:             "epusdt",
		AppURI:              "",
		HttpBindAddr:        "127.0.0.1",
		HttpBindPort:        8000,
		RuntimeRootPath:     "./runtime",
		LogSavePath:         "./logs",
		OrderExpirationTime: 10,
		OrderNoticeMaxRetry: 1,
	}
}

// installHandler holds the per-invocation state shared between handlers.
type installHandler struct {
	envFilePath string
	done        chan struct{}
}

func installRootRedirectMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.Request().Method == http.MethodGet && c.Request().URL.Path == "/" {
			return c.Redirect(http.StatusFound, "/install")
		}
		return next(c)
	}
}

func resolveInstallWWWRoot() string {
	// Resolve www/ relative to the executable so SPA routes work regardless
	// of the working directory. main.go extracts www/ next to the binary.
	wwwRoot := "./www"
	if exePath, err := os.Executable(); err == nil {
		if exePath, err = filepath.EvalSymlinks(exePath); err == nil {
			wwwRoot = filepath.Join(filepath.Dir(exePath), "www")
		}
	}
	return wwwRoot
}

func newInstallServer(envFilePath, wwwRoot string) (*echo.Echo, *installHandler) {
	h := &installHandler{
		envFilePath: envFilePath,
		done:        make(chan struct{}),
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// api routes for the install frontend
	api := e.Group("/api")

	api.GET("/install/defaults", h.GetDefaults)
	api.POST("/install", h.Submit)

	// Redirect browser visits on root to /install so first-run users land
	// on the wizard directly. This must run before the static middleware,
	// otherwise "/" is intercepted by the SPA index.html fallback.
	e.Use(installRootRedirectMiddleware)

	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Skipper: func(c echo.Context) bool {
			return luluHttp.ShouldSkipSPAFallback(c.Request().URL.Path)
		},
		HTML5: true,
		Index: "index.html",
		Root:  wwwRoot,
	}))

	return e, h
}

// GetDefaults returns default values for the install form.
//
// @Summary      Install — get default values
// @Description  Returns sensible default field values for the first-run install form.
//
//	Available only before the .env config file has been written.
//	After installation completes this route is no longer served.
//
// @Tags         Install
// @Produce      json
// @Success      200 {object} InstallRequest "Default install values"
// @Router       /api/install/defaults [get]
func (h *installHandler) GetDefaults(c echo.Context) error {
	return c.JSON(http.StatusOK, InstallDefaults())
}

// Submit validates the install payload, writes the .env file, initializes the
// minimum DB/admin state, and signals the install server to shut down so the
// main bootstrap can proceed.
// http_bind_addr and http_bind_port are combined as "ADDR:PORT" to produce
// the http_listen config key (e.g. 0.0.0.0:8000).
//
// @Summary      Install — submit configuration
// @Description  Validates the submitted configuration, writes install=true, performs the minimum DB setup needed to ensure the default admin exists, optionally returns init_password, then rewrites install=false before shutting down the install server.
// @Description  http_bind_addr + http_bind_port are joined internally as "ADDR:PORT" for http_listen. app_uri is required; other fields fall back to GET /api/install/defaults.
// @Tags         Install
// @Accept       json
// @Produce      json
// @Param        body body     InstallRequest true "Install configuration"
// @Success      200  {object} InstallSubmitResponse
// @Failure      400  {object} map[string]string "error"
// @Failure      500  {object} map[string]string "error"
// @Router       /api/install [post]
func (h *installHandler) Submit(c echo.Context) error {
	req := new(InstallRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
	}

	req.AppURI = strings.TrimSpace(req.AppURI)
	if req.AppURI == "" {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"error": "app_uri is required"})
	}
	if req.HttpBindPort != 0 && (req.HttpBindPort < 1 || req.HttpBindPort > 65535) {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"error": "http_bind_port must be between 1 and 65535"})
	}
	if err := validateInstallFields(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
	}
	d := InstallDefaults()
	if strings.TrimSpace(req.AppName) == "" {
		req.AppName = d.AppName
	}
	if strings.TrimSpace(req.HttpBindAddr) == "" {
		req.HttpBindAddr = d.HttpBindAddr
	}
	if req.HttpBindPort <= 0 {
		req.HttpBindPort = d.HttpBindPort
	}
	if strings.TrimSpace(req.RuntimeRootPath) == "" {
		req.RuntimeRootPath = d.RuntimeRootPath
	}
	if strings.TrimSpace(req.LogSavePath) == "" {
		req.LogSavePath = d.LogSavePath
	}
	if req.OrderExpirationTime <= 0 {
		req.OrderExpirationTime = d.OrderExpirationTime
	}
	if req.OrderNoticeMaxRetry < 0 {
		req.OrderNoticeMaxRetry = d.OrderNoticeMaxRetry
	}

	if err := writeEnvFile(h.envFilePath, req, true); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
	}
	initPassword, err := initializeInstallState(h.envFilePath)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
	}
	if err := writeEnvFile(h.envFilePath, req, false); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
	}

	go func() { close(h.done) }()
	// The generated administrator password is never part of the HTTP response:
	// anybody who can reach the wizard during the deployment window would
	// otherwise receive working credentials. It is printed once to the local
	// console instead, next to the same notice the bootstrap path prints.
	if strings.TrimSpace(initPassword) != "" {
		printInitialAdminPassword(initPassword)
	}
	return c.JSON(http.StatusOK, InstallSubmitResponse{
		Message: "install complete, starting server…",
	})
}

// RunInstallServer starts the install UI and REST API on listenAddr
// (default :8000), then blocks until installation has been finalized.
// The caller should then proceed with normal app initialisation (bootstrap.InitApp).
func RunInstallServer(listenAddr, envFilePath string) {
	if listenAddr == "" {
		listenAddr = DefaultInstallAddr
	}

	e, h := newInstallServer(envFilePath, resolveInstallWWWRoot())

	// Build a human-readable URL for the console hint.
	installHost := listenAddr
	if strings.HasPrefix(installHost, ":") {
		installHost = "localhost" + installHost
	}
	color.Green.Printf("[install] no config found — install API available at http://%s/install\n", installHost)

	go func() {
		<-h.done
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = e.Shutdown(ctx)
	}()

	if err := e.Start(listenAddr); err != nil && err != http.ErrServerClosed {
		color.Red.Printf("[install] server error: %s\n", err)
		os.Exit(1)
	}

	color.Green.Printf("[install] configuration saved to %s, starting…\n", envFilePath)
}

// formControlledKeys are keys whose values always come from the install form
// (or are set unconditionally by the template). Existing config values for
// these keys must NOT be preserved — the form submission takes precedence.
//
// order_expiration_time and order_notice_max_retry are deliberately absent: an
// operator who tuned them in .env keeps the tuned value across a re-install
// (the template still renders both, so the non-empty old value is substituted).
// writeEnvFile warns when the submitted form value differs from the value it
// keeps, so the form is never ignored silently.
var formControlledKeys = map[string]bool{
	"app_name":          true,
	"app_uri":           true,
	"http_listen":       true,
	"runtime_root_path": true,
	"log_save_path":     true,
	"install":           true,
}

// printInitialAdminPassword is a variable so tests can capture the console
// notice without a terminal.
var printInitialAdminPassword = func(password string) {
	color.Yellow.Printf("[install] initial admin password: %s\n", password)
	color.Yellow.Println("[install] save this now; it is not shown again and is not served over HTTP")
}

// validateInstallFields rejects submitted values that cannot be represented as a
// single line of the generated .env. The form's strings are substituted verbatim
// into the line-oriented config template, so an embedded newline would append an
// extra key of the submitter's choosing (for example a gmpay_signing_key, which is
// the seed every merchant notification is signed with) to the config that every
// later startup reads.
func validateInstallFields(r *InstallRequest) error {
	fields := []struct {
		key   string
		value string
	}{
		{"app_name", r.AppName},
		{"app_uri", r.AppURI},
		{"http_bind_addr", r.HttpBindAddr},
	}
	for _, field := range fields {
		if strings.ContainsAny(field.value, "\r\n\x00") {
			return fmt.Errorf("%s must not contain line breaks or NUL bytes", field.key)
		}
	}
	if err := validateInstallRuntimePath("runtime_root_path", r.RuntimeRootPath); err != nil {
		return err
	}
	return validateInstallRuntimePath("log_save_path", r.LogSavePath)
}

// validateInstallRuntimePath keeps the runtime directory inside the deployment.
//
// The wizard is unauthenticated, so an absolute path (or a Windows drive/UNC
// path, which a Linux host would still copy verbatim into .env for a Windows
// deployment) lets the caller point the runtime SQLite database and the daily log
// file at a location they control. On Windows a UNC path additionally makes the
// service authenticate against an attacker-controlled SMB host, leaking the
// service account's NetNTLMv2 response.
func validateInstallRuntimePath(key, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	if strings.ContainsAny(trimmed, "\r\n\x00") {
		return fmt.Errorf("%s must not contain line breaks or NUL bytes", key)
	}
	// Windows volume ("C:\...", "C:/...") and UNC ("\\host\share", "//host/share")
	// are rejected on every platform: the value is written to .env unchanged and
	// may be consumed by a Windows deployment.
	if len(trimmed) >= 2 && isWindowsDriveLetter(trimmed[0]) && trimmed[1] == ':' {
		return fmt.Errorf("%s must be a relative path", key)
	}
	if strings.HasPrefix(trimmed, `\\`) || strings.HasPrefix(trimmed, "//") {
		return fmt.Errorf("%s must be a relative path, not a network share", key)
	}
	if filepath.IsAbs(trimmed) {
		return fmt.Errorf("%s must be a relative path", key)
	}
	for _, segment := range strings.FieldsFunc(trimmed, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == ".." {
			return fmt.Errorf("%s must not contain '..' segments", key)
		}
	}
	return nil
}

func isWindowsDriveLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

type envTemplateData struct {
	*InstallRequest
	InstallValue string
}

// envLine is one key=value line of a .env file. lineIndex is the line's
// position in the original text so callers can rewrite it in place.
type envLine struct {
	lineIndex int
	key       string
	value     string
}

// parseEnvLines returns every key=value line of content in file order, skipping
// blank lines and comments. Keys and values are trimmed; a line without '=' is
// ignored, but a line whose key trims to empty is returned so callers can reject
// it instead of silently dropping configuration.
func parseEnvLines(content string) []envLine {
	lines := strings.Split(content, "\n")
	parsed := make([]envLine, 0, len(lines))
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		parsed = append(parsed, envLine{
			lineIndex: i,
			key:       strings.TrimSpace(key),
			value:     strings.TrimSpace(value),
		})
	}
	return parsed
}

// preservedEnvEntries selects the pairs a rewrite must keep from an existing
// .env: every key the install form does not own whose value is non-empty. A
// missing or empty value is not preserved, so the template (or the form) value
// still applies. First-seen order is kept so the rewrite is stable across runs,
// and a duplicated key keeps its first position with its last value.
func preservedEnvEntries(content string) []envLine {
	parsed := parseEnvLines(content)
	preserved := make([]envLine, 0, len(parsed))
	seen := make(map[string]int, len(parsed))
	for _, line := range parsed {
		if line.key == "" || line.value == "" || formControlledKeys[line.key] {
			continue
		}
		if i, ok := seen[line.key]; ok {
			preserved[i].value = line.value
			continue
		}
		seen[line.key] = len(preserved)
		preserved = append(preserved, line)
	}
	return preserved
}

// resolveEnvFileMode returns the mode for the rewritten .env and for its backup.
// The contract is "only tighter, never wider":
//   - no existing file: 0600, so a first install never exposes the file
//   - existing mode without group/other bits (e.g. 0400): keep it as-is
//   - anything else (0640, 0644, …): 0600
//
// Re-applying the old mode verbatim is forbidden: epctl:709 provisions the first
// .env as 0644, and honoring that would leave the signing key world-readable.
func resolveEnvFileMode(oldMode os.FileMode, exists bool) os.FileMode {
	if !exists {
		return 0o600
	}
	if mode := oldMode.Perm(); mode&0o077 == 0 {
		return mode
	}
	return 0o600
}

// verifyEnvContent enforces the post-write contract before the temporary file is
// renamed into place: every expected key appears exactly once, no key is
// duplicated, no line has an empty key, and no key outside the allowed set (the
// template's own keys plus the keys preserved from the previous file) appears at
// all. The last rule is the one that matters for a line-oriented format: it is
// the only check that does not trust the document being verified to describe
// itself.
func verifyEnvContent(content string, expectedKeys, allowedKeys []string) error {
	parsed := parseEnvLines(content)
	allowed := make(map[string]bool, len(allowedKeys))
	for _, key := range allowedKeys {
		allowed[key] = true
	}
	counts := make(map[string]int, len(parsed))
	for _, line := range parsed {
		if line.key == "" {
			return fmt.Errorf("generated config line %d has no key", line.lineIndex+1)
		}
		if !allowed[line.key] {
			return fmt.Errorf("generated config contains unexpected key %q", line.key)
		}
		counts[line.key]++
	}
	for _, key := range expectedKeys {
		if counts[key] == 0 {
			return fmt.Errorf("generated config is missing key %q", key)
		}
	}
	for key, n := range counts {
		if n > 1 {
			return fmt.Errorf("generated config contains key %q %d times", key, n)
		}
	}
	return nil
}

// writeEnvBackup copies the current .env next to it before the rewrite. Retention
// is deliberate: only one .env.bak.<unix-timestamp> is kept, because every extra
// copy is another readable copy of the signing key. The contents are never
// logged or archived.
func writeEnvBackup(path, content string, mode os.FileMode) error {
	backupPath := path + ".bak." + strconv.FormatInt(time.Now().Unix(), 10)
	if err := os.WriteFile(backupPath, []byte(content), mode); err != nil {
		return fmt.Errorf("write config backup: %w", err)
	}
	// os.WriteFile honors the umask and keeps the mode of an existing file; make
	// the policy explicit so the backup is never wider than the .env itself.
	if err := os.Chmod(backupPath, mode); err != nil {
		return fmt.Errorf("set config backup mode: %w", err)
	}

	dir, base := filepath.Dir(path), filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("list config directory: %w", err)
	}
	prefix := base + ".bak."
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		stale := filepath.Join(dir, entry.Name())
		if stale == backupPath {
			continue
		}
		if err := os.Remove(stale); err != nil {
			return fmt.Errorf("remove stale config backup: %w", err)
		}
	}
	return nil
}

// readEnvFile reads the existing .env so it can be preserved and backed up before
// being replaced. A missing file is not an error (first install); any other read
// failure is, because treating an unreadable config as missing would silently
// drop every operator setting on the next rewrite.
func readEnvFile(path string) (content string, mode os.FileMode, exists bool, err error) {
	raw, readErr := os.ReadFile(path)
	if errors.Is(readErr, fs.ErrNotExist) {
		return "", 0, false, nil
	}
	if readErr != nil {
		return "", 0, false, fmt.Errorf("read existing config file: %w", readErr)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		return "", 0, false, fmt.Errorf("stat existing config file: %w", statErr)
	}
	return string(raw), info.Mode(), true, nil
}

// writeEnvFile renders and atomically writes the .env file.
//
// Rewrite contract:
//   - Form-controlled keys always take the submitted value.
//   - Every other non-empty value from the existing file is kept. If the
//     template renders the key, the old value is substituted into that line; if
//     it does not (gmpay_*, mysql_*, tg_*, …), the pair is appended in its
//     original order, so a re-install cannot drop configuration the form never
//     knew about.
//   - The file mode only ever gets tighter; see resolveEnvFileMode.
//   - The previous file is copied to .env.bak.<unix-timestamp> (same mode
//     policy) before the rewrite.
//   - The content is verified after it is written and before it is renamed.
func writeEnvFile(path string, r *InstallRequest, installEnabled bool) error {
	// The template interpolates these fields verbatim into a line-oriented file,
	// so refuse multi-line values before anything is written, not just in the
	// HTTP handler: this function is the sink.
	if err := validateInstallFields(r); err != nil {
		return err
	}
	oldContent, oldMode, oldExists, err := readEnvFile(path)
	if err != nil {
		return err
	}
	preserved := preservedEnvEntries(oldContent)

	// order_expiration_time and order_notice_max_retry are no longer form
	// controlled, so a .env value wins over the submitted one. Say it out loud:
	// silently ignoring the form is its own outage.
	formValues := map[string]string{
		"order_expiration_time":  strconv.Itoa(r.OrderExpirationTime),
		"order_notice_max_retry": strconv.Itoa(r.OrderNoticeMaxRetry),
	}
	for _, line := range preserved {
		formValue, ok := formValues[line.key]
		if !ok || formValue == line.value {
			continue
		}
		message := fmt.Sprintf("form value %s=%s ignored, effective value %s=%s comes from .env",
			line.key, formValue, line.key, line.value)
		if appLog.Sugar != nil {
			appLog.Sugar.Warn("[install] " + message)
			continue
		}
		// The logger is initialized after bootstrap, which runs after the install
		// wizard; fall back to the console output this file already uses.
		color.Warn.Printf("[install] %s\n", message)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	mode := resolveEnvFileMode(oldMode, oldExists)
	if oldExists {
		if err := writeEnvBackup(path, oldContent, mode); err != nil {
			return err
		}
	}

	// Render the template into a buffer first.
	var buf bytes.Buffer
	renderData := envTemplateData{
		InstallRequest: r,
		InstallValue:   "false",
	}
	if installEnabled {
		renderData.InstallValue = "true"
	}
	if err := envTemplate.Execute(&buf, renderData); err != nil {
		return fmt.Errorf("render env template: %w", err)
	}

	// Substitute preserved values into the template lines that render the same
	// key, so the template default never clobbers operator configuration.
	preservedByKey := make(map[string]string, len(preserved))
	for _, line := range preserved {
		preservedByKey[line.key] = line.value
	}
	lines := strings.Split(buf.String(), "\n")
	for _, line := range parseEnvLines(buf.String()) {
		if line.key == "" {
			return errors.New("render env template: line without a key")
		}
		if value, ok := preservedByKey[line.key]; ok {
			lines[line.lineIndex] = line.key + "=" + value
		}
	}

	templateKeys := make(map[string]bool, len(envTemplateKeys))
	for _, key := range envTemplateKeys {
		templateKeys[key] = true
	}

	// Keys the template does not know must survive the rewrite: append them in
	// their original order, exactly once each. The expected and allowed key sets
	// come from the template text and the previous file, never from the rendered
	// document, so a value that smuggles in an extra line cannot vouch for it.
	expectedKeys := make([]string, 0, len(envTemplateKeys)+len(preserved))
	expectedKeys = append(expectedKeys, envTemplateKeys...)
	allowedKeys := make([]string, 0, len(envTemplateKeys)+len(preserved))
	allowedKeys = append(allowedKeys, envTemplateKeys...)
	appended := make([]string, 0, len(preserved))
	for _, line := range preserved {
		allowedKeys = append(allowedKeys, line.key)
		if templateKeys[line.key] {
			continue
		}
		appended = append(appended, line.key+"="+line.value)
		expectedKeys = append(expectedKeys, line.key)
	}
	content := strings.TrimRight(strings.Join(lines, "\n"), "\n")
	if len(appended) > 0 {
		content += "\n\n# kept from the previous .env: keys the install form does not manage\n" +
			strings.Join(appended, "\n")
	}
	content += "\n"

	f, err := os.CreateTemp(filepath.Dir(path), ".env.tmp.*")
	if err != nil {
		return fmt.Errorf("open temp config file: %w", err)
	}
	tempPath := f.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()
	if _, err = fmt.Fprint(f, content); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temp config file: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close temp config file: %w", err)
	}
	// CreateTemp always starts at 0600; apply the resolved policy explicitly so a
	// 0400 .env stays 0400 and a 0644 one is tightened.
	if err = os.Chmod(tempPath, mode); err != nil {
		return fmt.Errorf("set config file mode: %w", err)
	}

	// Verify what actually landed on disk before exposing it under the real name.
	written, err := os.ReadFile(tempPath)
	if err != nil {
		return fmt.Errorf("read temp config file: %w", err)
	}
	if err = verifyEnvContent(string(written), expectedKeys, allowedKeys); err != nil {
		return err
	}

	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace config file: %w", err)
	}
	return nil
}

func initializeInstallState(envFilePath string) (string, error) {
	if err := initInstallConfig(envFilePath); err != nil {
		return "", err
	}
	if err := initInstallDatabases(); err != nil {
		closeInstallDatabases()
		return "", err
	}
	defer closeInstallDatabases()

	password, created, err := data.EnsureDefaultAdmin()
	if err != nil {
		return "", err
	}
	if created {
		password = strings.TrimSpace(password)
		if password == "" {
			return "", errors.New("default admin created without initial password")
		}
		return password, nil
	}

	password, err = data.GetInitialAdminPassword()
	if err != nil {
		if errors.Is(err, data.ErrInitAdminPasswordUnavailable) || errors.Is(err, data.ErrInitAdminPasswordAlreadyFetched) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(password), nil
}

func initInstallConfig(envFilePath string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("init config: %v", recovered)
		}
	}()
	config.SetConfigPath(envFilePath)
	config.Init()
	return nil
}

func initInstallDatabases() error {
	if appLog.Sugar == nil {
		appLog.Sugar = zap.NewNop().Sugar()
	}
	if err := dao.DBInit(); err != nil {
		return fmt.Errorf("init store db: %w", err)
	}
	if err := dao.RuntimeInit(); err != nil {
		return fmt.Errorf("init runtime db: %w", err)
	}
	return nil
}

func closeInstallDatabases() {
	if dao.RuntimeDB != nil {
		if db, err := dao.RuntimeDB.DB(); err == nil {
			_ = db.Close()
		}
		dao.RuntimeDB = nil
	}
	if dao.Mdb != nil {
		if db, err := dao.Mdb.DB(); err == nil {
			_ = db.Close()
		}
		dao.Mdb = nil
	}
}

// envTemplateRaw is the .env skeleton the install form renders. It is kept as a
// plain constant so envTemplateKeys can be derived from the template text itself.
const envTemplateRaw = `app_name={{.AppName}}
app_uri={{.AppURI}}
log_level=info
http_access_log=false
sql_debug=false
http_listen={{.HttpBindAddr}}:{{.HttpBindPort}}

static_path=/static
runtime_root_path={{.RuntimeRootPath}}

log_save_path={{.LogSavePath}}
log_max_size=32
log_max_age=7
max_backups=3

# supported values: postgres,mysql,sqlite
db_type=sqlite

# sqlite primary database config
sqlite_database_filename=
sqlite_table_prefix=

# sqlite runtime store config
runtime_sqlite_filename=epusdt-runtime.db

# background scheduler config
queue_concurrency=10
queue_poll_interval_ms=1000
callback_retry_base_seconds=5

order_expiration_time={{.OrderExpirationTime}}
order_notice_max_retry={{.OrderNoticeMaxRetry}}

api_rate_url=

# Comma-separated proxy IPs / CIDRs whose forwarding headers are trusted.
# Empty trusts them only from loopback/link-local/private peers.
trusted_proxies=

# Set to true to re-run the install wizard on next startup.
install={{.InstallValue}}
`

var envTemplate = template.Must(template.New("env").Parse(envTemplateRaw))

// envTemplateKeys are the keys the template renders, extracted from the template
// text rather than from a rendered document. Deriving them from a rendered
// document would let a form value that smuggles in an extra line vouch for its
// own key, because verifyEnvContent's expected set is then built from the very
// content it is supposed to police.
var envTemplateKeys = envTemplateKeyNames(envTemplateRaw)

// envTemplateKeyNames returns the key of every key=value line in raw, skipping
// blank lines and comments.
func envTemplateKeyNames(raw string) []string {
	keys := make([]string, 0, 32)
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, _, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		keys = append(keys, strings.TrimSpace(key))
	}
	return keys
}
