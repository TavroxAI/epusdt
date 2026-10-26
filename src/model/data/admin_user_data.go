package data

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/dromara/carbon/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const defaultAdminUsername = "admin"
const InitialAdminPasswordHashAlgorithm = "sha256"

var (
	ErrInitAdminPasswordUnavailable    = errors.New("initial password unavailable")
	ErrInitAdminPasswordAlreadyFetched = errors.New("initial password already fetched")
)

// InitialAdminPasswordHashInfo is returned by the hash query endpoint
// so the frontend can detect whether the operator is still using the
// initial password.
type InitialAdminPasswordHashInfo struct {
	Algorithm       string `json:"algorithm" example:"sha256"`
	PasswordHash    string `json:"password_hash" example:"3f79bb7b435b05321651daefd374cdc9f5f72c467ea3f9f3c5f6e6d7e8f9a0b1"`
	PasswordChanged bool   `json:"password_changed" example:"false"`
	Available       bool   `json:"available" example:"true"`
}

// EnsureDefaultAdmin seeds an initial admin account when no admin user
// exists. The password is randomly generated and returned so the caller
// can print it to the console. Idempotent — subsequent calls return
// ("", false, nil).
func EnsureDefaultAdmin() (password string, created bool, err error) {
	if err := dao.Mdb.Transaction(func(tx *gorm.DB) error {
		if err := purgeDeletedInitialAdminPasswordPlainTx(tx); err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&mdb.AdminUser{}).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return nil
		}

		password = randomAdminPassword()
		hash, err := HashPassword(password)
		if err != nil {
			return err
		}
		user := &mdb.AdminUser{
			Username:     defaultAdminUsername,
			PasswordHash: hash,
			Status:       mdb.AdminUserStatusEnable,
		}
		if err := tx.Create(user).Error; err != nil {
			return err
		}
		if err := initAdminPasswordStateTx(tx, password); err != nil {
			return err
		}
		created = true
		return nil
	}); err != nil {
		return "", false, err
	}
	if created {
		cacheInitialAdminPasswordState(password)
	}
	return password, created, nil
}

// settingKeyCond builds a dialect-safe "key = ?" condition. The hand-quoted
// `key` form is MySQL-only; PostgreSQL renders it as a syntax error
// (SQLSTATE 42601), which used to abort admin seeding entirely.
func settingKeyCond(key string) map[string]any {
	return map[string]any{"key": key}
}

func purgeDeletedInitialAdminPasswordPlainTx(tx *gorm.DB) error {
	return tx.Unscoped().
		Where(settingKeyCond(mdb.SettingKeyInitAdminPasswordPlain)).
		Where("deleted_at IS NOT NULL").
		Delete(&mdb.Setting{}).Error
}

func randomAdminPassword() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// HashInitialAdminPassword fingerprints the initial plaintext password so
// the frontend can compare user input locally without exposing plaintext.
func HashInitialAdminPassword(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return fmt.Sprintf("%x", sum[:])
}

func initAdminPasswordState(plain string) error {
	if err := initAdminPasswordStateTx(dao.Mdb, plain); err != nil {
		return err
	}
	cacheInitialAdminPasswordState(plain)
	return nil
}

func initAdminPasswordStateTx(tx *gorm.DB, plain string) error {
	hash := HashInitialAdminPassword(plain)
	settings := []mdb.Setting{
		{
			Group: mdb.SettingGroupSystem, Key: mdb.SettingKeyInitAdminPasswordPlain,
			Value: plain, Type: mdb.SettingTypeString,
			Description: "Readable initial admin password until password change",
		},
		{
			Group: mdb.SettingGroupSystem, Key: mdb.SettingKeyInitAdminPasswordHash,
			Value: hash, Type: mdb.SettingTypeString,
			Description: "SHA-256 fingerprint for initial admin password",
		},
		{
			Group: mdb.SettingGroupSystem, Key: mdb.SettingKeyInitAdminPasswordFetched,
			Value: "false", Type: mdb.SettingTypeBool,
			Description: "Whether initial admin password plaintext has been cleared",
		},
		{
			Group: mdb.SettingGroupSystem, Key: mdb.SettingKeyInitAdminPasswordChanged,
			Value: "false", Type: mdb.SettingTypeBool,
			Description: "Whether initial admin password has been changed",
		},
	}
	for _, row := range settings {
		if err := upsertSettingRow(tx, row); err != nil {
			return err
		}
	}
	return nil
}

func cacheInitialAdminPasswordState(plain string) {
	hash := HashInitialAdminPassword(plain)
	settingsCacheMu.Lock()
	settingsCache[mdb.SettingKeyInitAdminPasswordPlain] = plain
	settingsCache[mdb.SettingKeyInitAdminPasswordHash] = hash
	settingsCache[mdb.SettingKeyInitAdminPasswordFetched] = "false"
	settingsCache[mdb.SettingKeyInitAdminPasswordChanged] = "false"
	settingsCacheMu.Unlock()
}

func upsertSettingRow(tx *gorm.DB, row mdb.Setting) error {
	updates := clause.AssignmentColumns([]string{"group", "value", "type", "description", "updated_at"})
	updates = append(updates, clause.Assignment{Column: clause.Column{Name: "deleted_at"}, Value: nil})
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: updates,
	}).Create(&row).Error
}

// GetInitialAdminPassword returns the initial admin password plaintext while
// it is still available. The plaintext remains readable until the admin
// password is changed, after which the stored plaintext is deleted.
func GetInitialAdminPassword() (string, error) {
	row := new(mdb.Setting)
	if err := dao.Mdb.Model(&mdb.Setting{}).
		Where(settingKeyCond(mdb.SettingKeyInitAdminPasswordPlain)).
		Limit(1).
		Find(row).Error; err != nil {
		return "", err
	}
	if row.ID != 0 && row.Value != "" {
		return row.Value, nil
	}

	var fetched mdb.Setting
	if err := dao.Mdb.Model(&mdb.Setting{}).
		Where(settingKeyCond(mdb.SettingKeyInitAdminPasswordFetched)).
		Limit(1).
		Find(&fetched).Error; err != nil {
		return "", err
	}
	if strings.EqualFold(strings.TrimSpace(fetched.Value), "true") {
		return "", ErrInitAdminPasswordAlreadyFetched
	}
	return "", ErrInitAdminPasswordUnavailable
}

func clearInitialAdminPasswordPlain(tx *gorm.DB) error {
	res := tx.Unscoped().
		Where(settingKeyCond(mdb.SettingKeyInitAdminPasswordPlain)).
		Delete(&mdb.Setting{})
	if res.Error != nil {
		return res.Error
	}
	if err := upsertSettingRow(tx, mdb.Setting{
		Group:       mdb.SettingGroupSystem,
		Key:         mdb.SettingKeyInitAdminPasswordFetched,
		Value:       "true",
		Type:        mdb.SettingTypeBool,
		Description: "Whether initial admin password plaintext has been cleared",
	}); err != nil {
		return err
	}
	return nil
}

// GetInitialAdminPasswordHashInfo returns the initial-password fingerprint
// and the changed-state flag used by the admin frontend.
func GetInitialAdminPasswordHashInfo() (*InitialAdminPasswordHashInfo, error) {
	hash := strings.TrimSpace(GetSettingString(mdb.SettingKeyInitAdminPasswordHash, ""))
	if hash == "" {
		return &InitialAdminPasswordHashInfo{
			Algorithm:       InitialAdminPasswordHashAlgorithm,
			PasswordHash:    "",
			PasswordChanged: true,
			Available:       false,
		}, nil
	}
	return &InitialAdminPasswordHashInfo{
		Algorithm:       InitialAdminPasswordHashAlgorithm,
		PasswordHash:    hash,
		PasswordChanged: GetSettingBool(mdb.SettingKeyInitAdminPasswordChanged, false),
		Available:       true,
	}, nil
}

// IsUsingInitialAdminPassword reports whether the current admin password is
// still considered the seeded initial password.
func IsUsingInitialAdminPassword() bool {
	hash := strings.TrimSpace(GetSettingString(mdb.SettingKeyInitAdminPasswordHash, ""))
	if hash == "" {
		return false
	}
	return !GetSettingBool(mdb.SettingKeyInitAdminPasswordChanged, false)
}

// HashPassword bcrypts a plaintext password.
func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyPassword compares a plaintext password against a bcrypt hash.
func VerifyPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// dummyPasswordHash is used to keep the cost of an unknown-username login equal
// to the cost of a wrong-password login. Without it, a missing row returns before
// bcrypt runs and the response time reveals whether the account exists.
var (
	dummyPasswordHashOnce sync.Once
	dummyPasswordHash     string
)

func compareAgainstDummyHash(plain string) {
	dummyPasswordHashOnce.Do(func() {
		if h, err := bcrypt.GenerateFromPassword([]byte(randomAdminPassword()), bcrypt.DefaultCost); err == nil {
			dummyPasswordHash = string(h)
		}
	})
	_ = bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(plain))
}

// VerifyLoginPassword verifies a login password in constant work regardless of
// whether the account exists: an empty hash (unknown username) still runs one
// bcrypt comparison against a throwaway hash.
func VerifyLoginPassword(hash, plain string) bool {
	if strings.TrimSpace(hash) == "" {
		compareAgainstDummyHash(plain)
		return false
	}
	return VerifyPassword(hash, plain)
}

// BumpAdminSessionVersion invalidates every token issued for the user so far.
// It is called on logout and on password change; CheckAdminJWT compares the
// token's stamped version against this value on every request.
func BumpAdminSessionVersion(id uint64) error {
	if id == 0 {
		return nil
	}
	return dao.Mdb.Model(&mdb.AdminUser{}).
		Where("id = ?", id).
		Update("session_version", gorm.Expr("session_version + 1")).Error
}

// GetAdminUserByUsername returns the row for a username (case-insensitive).
func GetAdminUserByUsername(username string) (*mdb.AdminUser, error) {
	u := new(mdb.AdminUser)
	err := dao.Mdb.Model(u).
		Where("username = ?", strings.ToLower(strings.TrimSpace(username))).
		Limit(1).Find(u).Error
	return u, err
}

// GetAdminUserByID returns the row for an ID.
func GetAdminUserByID(id uint64) (*mdb.AdminUser, error) {
	u := new(mdb.AdminUser)
	err := dao.Mdb.Model(u).Limit(1).Find(u, id).Error
	return u, err
}

// UpdateAdminUserPassword rehashes and persists a new password. When the
// change succeeds, the stored initial-password plaintext is deleted so it can
// no longer be returned by the install flow.
func UpdateAdminUserPassword(id uint64, newPlain string) error {
	hash, err := HashPassword(newPlain)
	if err != nil {
		return err
	}
	clearedPlaintext := false
	changedCacheValue := ""
	err = dao.Mdb.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&mdb.AdminUser{}).
			Where("id = ?", id).
			Updates(map[string]interface{}{
				"password_hash":   hash,
				"session_version": gorm.Expr("session_version + 1"),
			}).Error; err != nil {
			return err
		}

		var plainRow mdb.Setting
		if err := tx.Model(&mdb.Setting{}).
			Where(settingKeyCond(mdb.SettingKeyInitAdminPasswordPlain)).
			Limit(1).
			Find(&plainRow).Error; err != nil {
			return err
		}
		hasPlaintext := plainRow.ID != 0 && strings.TrimSpace(plainRow.Value) != ""

		// Old installs may not have initial-password metadata; skip in
		// that case to keep password_changed backward compatible, but still
		// clear any leftover plaintext if it exists.
		var initHashRow mdb.Setting
		if err := tx.Model(&mdb.Setting{}).
			Where(settingKeyCond(mdb.SettingKeyInitAdminPasswordHash)).
			Limit(1).
			Find(&initHashRow).Error; err != nil {
			return err
		}
		initHash := strings.TrimSpace(initHashRow.Value)
		if initHash == "" {
			if hasPlaintext {
				if err := clearInitialAdminPasswordPlain(tx); err != nil {
					return err
				}
				clearedPlaintext = true
			}
			return nil
		}

		newHash := HashInitialAdminPassword(newPlain)
		changed := subtle.ConstantTimeCompare([]byte(initHash), []byte(newHash)) != 1
		changedValue := "true"
		if !changed {
			changedValue = "false"
		}
		if err := upsertSettingRow(tx, mdb.Setting{
			Group:       mdb.SettingGroupSystem,
			Key:         mdb.SettingKeyInitAdminPasswordChanged,
			Value:       changedValue,
			Type:        mdb.SettingTypeBool,
			Description: "Whether initial admin password has been changed",
		}); err != nil {
			return err
		}
		if err := clearInitialAdminPasswordPlain(tx); err != nil {
			return err
		}
		clearedPlaintext = true
		changedCacheValue = changedValue
		return nil
	})
	if err != nil {
		return err
	}
	if clearedPlaintext || changedCacheValue != "" {
		settingsCacheMu.Lock()
		if clearedPlaintext {
			delete(settingsCache, mdb.SettingKeyInitAdminPasswordPlain)
			settingsCache[mdb.SettingKeyInitAdminPasswordFetched] = "true"
		}
		if changedCacheValue != "" {
			settingsCache[mdb.SettingKeyInitAdminPasswordChanged] = changedCacheValue
		}
		settingsCacheMu.Unlock()
	}
	return nil
}

// TouchAdminUserLastLogin stamps last_login_at to now.
func TouchAdminUserLastLogin(id uint64) error {
	return dao.Mdb.Model(&mdb.AdminUser{}).
		Where("id = ?", id).
		Update("last_login_at", carbon.Now().StdTime()).Error
}
