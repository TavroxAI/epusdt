package mdb

import "github.com/dromara/carbon/v2"

const (
	AdminUserStatusEnable  = 1
	AdminUserStatusDisable = 2
)

type AdminUser struct {
	Username     string `gorm:"column:username;uniqueIndex:admin_users_username_uindex;size:64" json:"username" example:"admin"`
	PasswordHash string `gorm:"column:password_hash;size:255" json:"-"`
	// SessionVersion is stamped into every issued token. Bumping it (logout,
	// password change) invalidates all tokens issued before the bump, which is
	// what lets a stateless JWT session be revoked.
	SessionVersion int64 `gorm:"column:session_version;default:0" json:"-"`
	// 状态 1=启用 2=禁用
	Status      int         `gorm:"column:status;default:1" json:"status" enums:"1,2" example:"1"`
	LastLoginAt carbon.Time `gorm:"column:last_login_at" json:"last_login_at" example:"2026-04-16 12:00:00"`
	BaseModel
}

func (a *AdminUser) TableName() string {
	return "admin_users"
}
