package controller

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/GMWalletApp/epusdt/util/constant"
	"github.com/labstack/echo/v4"
)

type concurrencyProbePayload struct {
	Name string `json:"name" validate:"required"`
}

// TestValidateStructIsConcurrencySafe reproduces the reported crash: validating
// two requests at the same time used to write the package-level locale message
// map from every handler, which aborts the process with
// "fatal error: concurrent map writes" — an unrecoverable runtime error, not a
// panic, so middleware could not contain it. Run with -race as well; the race
// detector reports the same defect without needing to lose the scheduler lottery.
func TestValidateStructIsConcurrencySafe(t *testing.T) {
	const goroutines = 16
	const iterations = 20

	e := echo.New()
	ctrl := &BaseController{}
	locales := []string{"", "zh", "zh-tw"}
	failures := make(chan string, goroutines)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				req := httptest.NewRequest(http.MethodPost, "/", nil)
				locale := locales[(g+i)%len(locales)]
				req.Header.Set("locale", locale)
				ctx := e.NewContext(req, httptest.NewRecorder())

				if err := ctrl.ValidateStruct(ctx, concurrencyProbePayload{Name: "ok"}); err != nil {
					failures <- "valid payload rejected: " + err.Error()
					return
				}
				if err := ctrl.ValidateStruct(ctx, concurrencyProbePayload{}); err != constant.ParamsMarshalErr {
					failures <- "invalid payload error mismatch"
					return
				}
				if got := ctrl.GetLocale(ctx); got != locale {
					failures <- "locale leaked between requests"
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(failures)

	for msg := range failures {
		t.Error(msg)
	}
}

// TestGetLocaleDoesNotMutateController makes the invariant explicit: the shared
// Ctrl instance must carry no per-request state.
func TestGetLocaleDoesNotMutateController(t *testing.T) {
	e := echo.New()
	ctrl := &BaseController{}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("locale", "zh-tw")
	if got := ctrl.GetLocale(e.NewContext(req, httptest.NewRecorder())); got != "zh-tw" {
		t.Fatalf("GetLocale = %q, want zh-tw", got)
	}

	other := httptest.NewRequest(http.MethodPost, "/", nil)
	if got := ctrl.GetLocale(e.NewContext(other, httptest.NewRecorder())); got != "" {
		t.Fatalf("GetLocale on a request without the header = %q, want empty", got)
	}
}
