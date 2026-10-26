package route

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GMWalletApp/epusdt/controller/admin"
	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/model/mdb"
)

// TestAdminSettingsCannotRewriteCredentialKeys covers vuln-0009: the settings
// batch upsert must not be able to replace system.jwt_secret (the key that signs
// admin sessions) or the initial-password state the console hides.
func TestAdminSettingsCannotRewriteCredentialKeys(t *testing.T) {
	e, token := setupAdminTestEnv(t)

	secretBefore := data.GetSettingString(mdb.SettingKeyJwtSecret, "")
	if secretBefore == "" {
		t.Fatal("expected a seeded jwt secret")
	}

	for _, key := range []string{
		mdb.SettingKeyJwtSecret,
		mdb.SettingKeyInitAdminPasswordHash,
		mdb.SettingKeyInitAdminPasswordChanged,
		"system.unknown_key",
	} {
		t.Run(key, func(t *testing.T) {
			rec := doPutAdmin(e, "/admin/api/v1/settings", map[string]interface{}{
				"items": []map[string]interface{}{
					{"group": "system", "key": key, "value": "attacker-controlled", "type": "string"},
				},
			}, token)
			resp := assertOK(t, rec)
			rows, _ := resp["data"].([]interface{})
			if len(rows) != 1 {
				t.Fatalf("expected one result row, got %v", resp["data"])
			}
			row, _ := rows[0].(map[string]interface{})
			if ok, _ := row["ok"].(bool); ok {
				t.Fatalf("write to %s was accepted", key)
			}
			if got, _ := row["error_code"].(float64); got != 10043 {
				t.Fatalf("error_code = %v, want 10043; row=%v", row["error_code"], row)
			}
		})
	}

	if after := data.GetSettingString(mdb.SettingKeyJwtSecret, ""); after != secretBefore {
		t.Fatalf("jwt secret changed from %q to %q", secretBefore, after)
	}

	// A legitimate key still writes, so the allowlist did not close the console.
	rec := doPutAdmin(e, "/admin/api/v1/settings", map[string]interface{}{
		"items": []map[string]interface{}{
			{"group": "brand", "key": mdb.SettingKeyBrandSiteTitle, "value": "Epusdt", "type": "string"},
		},
	}, token)
	resp := assertOK(t, rec)
	rows, _ := resp["data"].([]interface{})
	if len(rows) != 1 {
		t.Fatalf("expected one result row, got %v", resp["data"])
	}
	if row, _ := rows[0].(map[string]interface{}); row["ok"] != true {
		t.Fatalf("legitimate setting rejected: %v", row)
	}
}

// TestAdminSettingsCannotDeleteCredentialKeys is the delete half of the same
// allowlist: removing system.jwt_secret would silently rotate the session key.
func TestAdminSettingsCannotDeleteCredentialKeys(t *testing.T) {
	e, token := setupAdminTestEnv(t)

	secretBefore := data.GetSettingString(mdb.SettingKeyJwtSecret, "")
	for _, key := range []string{mdb.SettingKeyJwtSecret, mdb.SettingKeyInitAdminPasswordHash} {
		rec := doDeleteAdmin(e, "/admin/api/v1/settings/"+key, token)
		assertErrorCode(t, rec, 10043)
	}
	if after := data.GetSettingString(mdb.SettingKeyJwtSecret, ""); after != secretBefore {
		t.Fatalf("jwt secret changed after a rejected delete")
	}
}

// TestAdminLoginThrottlesFailures covers vuln-0015: repeated failures must stop
// being actionable instead of granting unbounded guesses.
func TestAdminLoginThrottlesFailures(t *testing.T) {
	e := setupTestEnv(t)
	hash, _ := data.HashPassword(testAdminPassword)
	if err := dao.Mdb.Create(&mdb.AdminUser{
		Username:     testAdminUsername,
		PasswordHash: hash,
		Status:       mdb.AdminUserStatusEnable,
	}).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	login := func(password string) *httptest.ResponseRecorder {
		return doPost(e, "/admin/api/v1/auth/login", map[string]interface{}{
			"username": testAdminUsername,
			"password": password,
		})
	}

	for i := 0; i < admin.AdminLoginMaxFailuresForTest(); i++ {
		rec := login("wrong-password")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: status = %d, want 400; body=%s", i+1, rec.Code, rec.Body.String())
		}
	}

	rec := login("wrong-password")
	assertErrorCode(t, rec, 10048)
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Fatal("blocked response is missing Retry-After")
	}

	// Even the correct password is refused while the client is blocked: the
	// budget belongs to the client, not to the guess.
	if retry := login(testAdminPassword).Header().Get("Retry-After"); retry == "" {
		t.Fatal("correct password bypassed the block")
	}
}

// TestAdminLoginDoesNotRevealUnknownUsernames covers the enumeration half of
// vuln-0015: an unknown username and a wrong password must be indistinguishable.
func TestAdminLoginDoesNotRevealUnknownUsernames(t *testing.T) {
	e := setupTestEnv(t)
	hash, _ := data.HashPassword(testAdminPassword)
	if err := dao.Mdb.Create(&mdb.AdminUser{
		Username:     testAdminUsername,
		PasswordHash: hash,
		Status:       mdb.AdminUserStatusEnable,
	}).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	statusOf := func(username, password string) (int, int, string) {
		rec := doPost(e, "/admin/api/v1/auth/login", map[string]interface{}{
			"username": username,
			"password": password,
		})
		var resp map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		code, _ := resp["status_code"].(float64)
		message, _ := resp["message"].(string)
		return rec.Code, int(code), message
	}

	wrongHTTP, wrongCode, wrongMessage := statusOf(testAdminUsername, "wrong-password")
	unknownHTTP, unknownCode, unknownMessage := statusOf("no-such-operator", "wrong-password")

	if wrongHTTP != unknownHTTP || wrongCode != unknownCode || wrongMessage != unknownMessage {
		t.Fatalf("unknown user (%d/%d/%q) differs from wrong password (%d/%d/%q)",
			unknownHTTP, unknownCode, unknownMessage, wrongHTTP, wrongCode, wrongMessage)
	}
	if wrongCode != 10025 {
		t.Fatalf("status_code = %d, want 10025", wrongCode)
	}
}

// TestAdminDisabledAccountRevokesSession covers the session half of vuln-0011 at
// the HTTP boundary: disabling the account kills the existing token and refuses
// a fresh login with the correct password.
func TestAdminDisabledAccountRevokesSession(t *testing.T) {
	e, token := setupAdminTestEnv(t)

	if err := dao.Mdb.Model(&mdb.AdminUser{}).
		Where("username = ?", testAdminUsername).
		Update("status", mdb.AdminUserStatusDisable).Error; err != nil {
		t.Fatalf("disable admin: %v", err)
	}

	assertUnauthorized(t, doGetAdmin(e, "/admin/api/v1/auth/me", token))
	assertErrorCode(t, doPost(e, "/admin/api/v1/auth/login", map[string]interface{}{
		"username": testAdminUsername,
		"password": testAdminPassword,
	}), 10026)
}

// TestAdminDeletedAccountRevokesSession makes the "delete the account" case
// explicit: the uid claim alone must not authenticate anyone.
func TestAdminDeletedAccountRevokesSession(t *testing.T) {
	e, token := setupAdminTestEnv(t)

	if err := dao.Mdb.Where("username = ?", testAdminUsername).Delete(&mdb.AdminUser{}).Error; err != nil {
		t.Fatalf("delete admin: %v", err)
	}
	assertUnauthorized(t, doGetAdmin(e, "/admin/api/v1/auth/me", token))
}
