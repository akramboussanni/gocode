package model

type User struct {
	ID                   int64  `db:"id"`
	Username             string `db:"username"`
	Email                string `db:"email"`
	PasswordHash         string `db:"password_hash"`
	CreatedAt            int64  `db:"created_at"`
	Role                 string `db:"user_role"`
	EmailConfirmed       bool   `db:"email_confirmed"`
	EmailConfirmToken    string `db:"email_confirm_token"`
	EmailConfirmIssuedat string `db:"email_confirm_issuedat"`
}
