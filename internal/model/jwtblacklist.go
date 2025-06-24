package model

type JwtBlacklist struct {
	TokenID   string `db:"jti"`
	UserID    int64  `db:"user_id"`
	ExpiresAt string `db:"expires_at"`
}
