package admin

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/GMWalletApp/epusdt/util/constant"
	appjwt "github.com/GMWalletApp/epusdt/util/jwt"
	"github.com/GMWalletApp/epusdt/util/ratelimit"
	"github.com/labstack/echo/v4"
)

// Admin login throttling. A single administrative account with unlimited guesses
// is the cheapest way into the console, and the console exposes every merchant
// secret and can repoint payouts, so failures are budgeted per client address.
const (
	adminLoginMaxFailures   = 10
	adminLoginFailureWindow = 15 * time.Minute
)

// adminLoginLimiter is a package variable so tests can substitute a limiter with
// a controlled clock. It counts failures per client address.
var adminLoginLimiter = ratelimit.New(adminLoginMaxFailures, adminLoginFailureWindow)

// ResetLoginAttemptsForTest clears the login budget. Tests across packages drive
// the HTTP surface from one shared httptest address, so they must start clean.
func ResetLoginAttemptsForTest() {
	adminLoginLimiter = ratelimit.New(adminLoginMaxFailures, adminLoginFailureWindow)
}

// AdminLoginMaxFailuresForTest exposes the failure budget so HTTP-level tests can
// spend exactly one budget instead of hard-coding the number.
func AdminLoginMaxFailuresForTest() int {
	return adminLoginMaxFailures
}

// LoginRequest is the payload for admin login.
type LoginRequest struct {
	Username string `json:"username" validate:"required" example:"admin"`
	Password string `json:"password" validate:"required" example:"password123"`
}

// LoginResponse is the response for a successful login.
type LoginResponse struct {
	Token    string `json:"token" example:"eyJhbGciOiJIUzI1NiIs..."`
	Username string `json:"username" example:"admin"`
	UserID   uint64 `json:"user_id" example:"1"`
}

// ChangePasswordRequest is the payload for changing admin password.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required" example:"old_pass"`
	NewPassword string `json:"new_password" validate:"required|minLen:6" example:"new_pass123"`
}

// MeResponse wraps AdminUser with a default-password flag.
type MeResponse struct {
	mdb.AdminUser
	PasswordIsDefault bool `json:"password_is_default" example:"true"`
}

// Login verifies credentials, stamps last_login_at, returns a signed JWT.
//
// Failures are budgeted per client address so password guessing and the
// enumeration it enables are bounded; an unknown username still pays one bcrypt
// comparison, so the response time does not tell an attacker whether the account
// exists.
// @Summary      Admin login
// @Description  Verify credentials and return a signed JWT token
// @Tags         Admin Auth
// @Accept       json
// @Produce      json
// @Param        request body admin.LoginRequest true "Login credentials"
// @Success      200 {object} response.ApiResponse{data=admin.LoginResponse}
// @Failure      400 {object} response.ApiResponse
// @Router       /admin/api/v1/auth/login [post]
func (c *BaseAdminController) Login(ctx echo.Context) error {
	req := new(LoginRequest)
	if err := ctx.Bind(req); err != nil {
		return c.FailJson(ctx, constant.ParamsMarshalErr)
	}
	if err := c.ValidateStruct(ctx, req); err != nil {
		return c.FailJson(ctx, err)
	}

	attemptKey := strings.TrimSpace(ctx.RealIP())
	if allowed, retryAfter := adminLoginLimiter.Allow(attemptKey); !allowed {
		ctx.Response().Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
		return c.FailJson(ctx, constant.AdminLoginRateLimitedErr)
	}

	user, err := data.GetAdminUserByUsername(req.Username)
	if err != nil {
		return c.FailJson(ctx, err)
	}
	hash := ""
	if user.ID != 0 {
		hash = user.PasswordHash
	}
	if !data.VerifyLoginPassword(hash, req.Password) {
		adminLoginLimiter.Fail(attemptKey)
		return c.FailJson(ctx, constant.AdminInvalidCredentialErr)
	}
	// A disabled account is reported only after the password checked out, so the
	// distinct error cannot be used to enumerate usernames.
	if user.Status != mdb.AdminUserStatusEnable {
		adminLoginLimiter.Fail(attemptKey)
		return c.FailJson(ctx, constant.AdminUserDisabledErr)
	}
	adminLoginLimiter.Reset(attemptKey)

	token, err := appjwt.Sign(user.ID, user.Username, user.SessionVersion)
	if err != nil {
		return c.FailJson(ctx, err)
	}
	err = data.TouchAdminUserLastLogin(user.ID)
	if err != nil {
		return c.FailJson(ctx, err)
	}
	return c.SucJson(ctx, LoginResponse{
		Token:    token,
		Username: user.Username,
		UserID:   user.ID,
	})
}

// GetInitialPasswordHash returns the initial-password fingerprint so the
// frontend can warn until the password is changed.
//
// It is an authenticated endpoint: the returned value is a verifier for the
// highest-privileged account on the instance, and an unauthenticated caller
// could use it to test guesses offline, outside any rate limit and without a log
// entry.
// @Summary      Get initial admin password hash
// @Description  Returns the initial password hash and password-changed flag.
// @Tags         Admin Auth
// @Security     AdminJWT
// @Produce      json
// @Success      200 {object} response.ApiResponse{data=data.InitialAdminPasswordHashInfo}
// @Failure      400 {object} response.ApiResponse
// @Router       /admin/api/v1/auth/init-password-hash [get]
func (c *BaseAdminController) GetInitialPasswordHash(ctx echo.Context) error {
	info, err := data.GetInitialAdminPasswordHashInfo()
	if err != nil {
		return c.FailJson(ctx, err)
	}
	return c.SucJson(ctx, info)
}

// Logout revokes every token issued for the current admin user by bumping the
// account's session version. Tokens are stateless, so this is what makes "log
// out" actually mean something.
// @Summary      Admin logout
// @Description  Revoke the current admin user's issued tokens
// @Tags         Admin Auth
// @Security     AdminJWT
// @Produce      json
// @Success      200 {object} response.ApiResponse
// @Router       /admin/api/v1/auth/logout [post]
func (c *BaseAdminController) Logout(ctx echo.Context) error {
	uid := currentAdminUserID(ctx)
	if uid == 0 {
		return c.FailJson(ctx, constant.AdminUnauthorizedErr)
	}
	if err := data.BumpAdminSessionVersion(uid); err != nil {
		return c.FailJson(ctx, err)
	}
	return c.SucJson(ctx, nil)
}

// Me returns the currently authenticated admin user profile.
// @Summary      Get current admin profile
// @Description  Returns the currently authenticated admin user
// @Tags         Admin Auth
// @Security     AdminJWT
// @Produce      json
// @Success      200 {object} response.ApiResponse{data=admin.MeResponse}
// @Failure      400 {object} response.ApiResponse
// @Router       /admin/api/v1/auth/me [get]
func (c *BaseAdminController) Me(ctx echo.Context) error {
	uid := currentAdminUserID(ctx)
	if uid == 0 {
		return c.FailJson(ctx, constant.AdminUnauthorizedErr)
	}
	user, err := data.GetAdminUserByID(uid)
	if err != nil {
		return c.FailJson(ctx, err)
	}
	if user.ID == 0 {
		return c.FailJson(ctx, constant.AdminUserNotFoundErr)
	}
	// Warn the frontend when the operator hasn't changed the seeded
	// initial password.
	isDefault := data.IsUsingInitialAdminPassword()
	return c.SucJson(ctx, MeResponse{
		AdminUser:         *user,
		PasswordIsDefault: isDefault,
	})
}

// ChangePassword requires the old password, updates to the new one.
//
// Changing the password bumps the account's session version, so tokens issued
// before the change stop working: the caller must log in again with the new
// password, and any stolen session does not survive the rotation.
// @Summary      Change admin password
// @Description  Change the current admin user's password
// @Tags         Admin Auth
// @Security     AdminJWT
// @Accept       json
// @Produce      json
// @Param        request body admin.ChangePasswordRequest true "Password payload"
// @Success      200 {object} response.ApiResponse
// @Failure      400 {object} response.ApiResponse
// @Router       /admin/api/v1/auth/password [post]
func (c *BaseAdminController) ChangePassword(ctx echo.Context) error {
	uid := currentAdminUserID(ctx)
	if uid == 0 {
		return c.FailJson(ctx, constant.AdminUnauthorizedErr)
	}
	req := new(ChangePasswordRequest)
	if err := ctx.Bind(req); err != nil {
		return c.FailJson(ctx, constant.ParamsMarshalErr)
	}
	if err := c.ValidateStruct(ctx, req); err != nil {
		return c.FailJson(ctx, err)
	}
	user, err := data.GetAdminUserByID(uid)
	if err != nil {
		return c.FailJson(ctx, err)
	}
	if user.ID == 0 || !data.VerifyPassword(user.PasswordHash, req.OldPassword) {
		return c.FailJson(ctx, constant.AdminOldPasswordErr)
	}
	if err := data.UpdateAdminUserPassword(uid, req.NewPassword); err != nil {
		return c.FailJson(ctx, err)
	}
	return c.SucJson(ctx, nil)
}
