package model

type User struct {
	ID                   int64  `db:"id" safe:"true" json:"id"`
	Username             string `db:"username" safe:"true" json:"username"`
	Email                string `db:"email" safe:"true" json:"email"`
	PasswordHash         string `db:"password_hash" json:"-"`
	CreatedAt            int64  `db:"created_at" safe:"true" json:"created_at"`
	Role                 string `db:"user_role" safe:"true" json:"role"`
	EmailConfirmed       bool   `db:"email_confirmed" json:"-"`
	EmailConfirmToken    string `db:"email_confirm_token" json:"-"`
	EmailConfirmIssuedAt int64  `db:"email_confirm_issuedat" json:"-"`
}
