package controller

import (
	"sync"

	"github.com/GMWalletApp/epusdt/util/constant"
	"github.com/GMWalletApp/epusdt/util/http"
	"github.com/gookit/validate"
	"github.com/gookit/validate/locales/zhcn"
	"github.com/gookit/validate/locales/zhtw"
	"github.com/labstack/echo/v4"
)

var Ctrl = &BaseController{}

type validatorBase struct {
	once     sync.Once
	validate *validate.Validation
}

// BaseController is a process-wide singleton (Ctrl). It must not carry any
// per-request state: concurrent handlers would race on it.
type BaseController struct {
	http.Resp
	Validator validatorBase
}

// GetLocale returns the requested locale. The value is derived from the request
// and never stored on the controller, because the controller is shared by every
// concurrent request.
func (c *BaseController) GetLocale(ctx echo.Context) string {
	return ctx.Request().Header.Get("locale")
}

// RegisterGlobal is kept for source compatibility and does nothing.
//
// gookit/validate keeps its builtin messages in a package-level map, and
// zhcn.RegisterGlobal/zhtw.RegisterGlobal write that map with no
// synchronisation. Calling them on every request therefore raced between
// concurrent requests and aborted the whole process with
// "fatal error: concurrent map writes", which is not a panic and so cannot be
// recovered by middleware. Locale messages are now applied to the per-request
// validation in ValidateStruct, which only touches that request's Validation.
func (c *BaseController) RegisterGlobal(ctx echo.Context) {
	_ = c.GetLocale(ctx)
}

func (c *BaseController) ValidateStruct(ctx echo.Context, i interface{}, scene ...string) error {
	v := validate.Struct(i, scene...)
	switch c.GetLocale(ctx) {
	case "zh-tw":
		zhtw.Register(v)
	default:
		zhcn.Register(v)
	}
	if v.Validate() {
		return nil
	}
	return constant.ParamsMarshalErr
}
