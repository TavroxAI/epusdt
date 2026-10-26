package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GMWalletApp/epusdt/internal/testutil"
	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/model/mdb"
	appjwt "github.com/GMWalletApp/epusdt/util/jwt"
	"github.com/labstack/echo/v4"
)

func TestAdminTokenFromAuthorization(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{
			name:   "bearer token",
			header: "Bearer jwt-token",
			want:   "jwt-token",
		},
		{
			name:   "bare token",
			header: "jwt-token",
			want:   "jwt-token",
		},
		{
			name:   "trimmed bare token",
			header: "  jwt-token  ",
			want:   "jwt-token",
		},
		{
			name:    "missing header",
			header:  "",
			wantErr: true,
		},
		{
			name:    "empty bearer token",
			header:  "Bearer ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := adminTokenFromAuthorization(tt.header)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("token = %q, want %q", got, tt.want)
			}
		})
	}
}

func seedAdminUser(t *testing.T, status int) *mdb.AdminUser {
	t.Helper()

	hash, err := data.HashPassword("test-admin-pass-123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &mdb.AdminUser{
		Username:     "admin",
		PasswordHash: hash,
		Status:       status,
	}
	if err := dao.Mdb.Create(user).Error; err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	return user
}

func newAdminJWTRouter() *echo.Echo {
	e := echo.New()
	e.Use(CheckAdminJWT())
	e.GET("/", func(ctx echo.Context) error {
		return ctx.NoContent(http.StatusNoContent)
	})
	return e
}

func serveAdminJWTRequest(e *echo.Echo, header string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(echo.HeaderAuthorization, header)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec.Code
}

func TestCheckAdminJWTRequiresLiveAccount(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	if err := data.SetSetting(mdb.SettingGroupSystem, mdb.SettingKeyJwtSecret, "test-jwt-secret", mdb.SettingTypeString); err != nil {
		t.Fatalf("seed jwt secret: %v", err)
	}
	user := seedAdminUser(t, mdb.AdminUserStatusEnable)

	token, err := appjwt.Sign(user.ID, user.Username, user.SessionVersion)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	e := newAdminJWTRouter()

	for _, header := range []string{"Bearer " + token, token} {
		if code := serveAdminJWTRequest(e, header); code != http.StatusNoContent {
			t.Fatalf("valid token rejected: status=%d", code)
		}
	}

	// Logout/password change bump the session version; the old token dies.
	if err := data.BumpAdminSessionVersion(user.ID); err != nil {
		t.Fatalf("bump session version: %v", err)
	}
	if code := serveAdminJWTRequest(e, "Bearer "+token); code != http.StatusUnauthorized {
		t.Fatalf("token from a previous session accepted: status=%d", code)
	}

	// A fresh login (new version) works again.
	reloaded, err := data.GetAdminUserByID(user.ID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	fresh, err := appjwt.Sign(reloaded.ID, reloaded.Username, reloaded.SessionVersion)
	if err != nil {
		t.Fatalf("sign fresh jwt: %v", err)
	}
	if code := serveAdminJWTRequest(e, "Bearer "+fresh); code != http.StatusNoContent {
		t.Fatalf("fresh token rejected: status=%d", code)
	}

	// Disabling the account revokes access without touching the token.
	if err := dao.Mdb.Model(&mdb.AdminUser{}).Where("id = ?", user.ID).Update("status", mdb.AdminUserStatusDisable).Error; err != nil {
		t.Fatalf("disable admin: %v", err)
	}
	if code := serveAdminJWTRequest(e, "Bearer "+fresh); code != http.StatusUnauthorized {
		t.Fatalf("token for a disabled account accepted: status=%d", code)
	}

	// Deleting the account revokes access as well.
	if err := dao.Mdb.Model(&mdb.AdminUser{}).Where("id = ?", user.ID).Update("status", mdb.AdminUserStatusEnable).Error; err != nil {
		t.Fatalf("re-enable admin: %v", err)
	}
	if err := dao.Mdb.Delete(&mdb.AdminUser{}, user.ID).Error; err != nil {
		t.Fatalf("delete admin: %v", err)
	}
	if code := serveAdminJWTRequest(e, "Bearer "+fresh); code != http.StatusUnauthorized {
		t.Fatalf("token for a deleted account accepted: status=%d", code)
	}
}
