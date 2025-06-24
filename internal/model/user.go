package model

type User struct {
	ID           int64  `db:"id"`
	Username     string `db:"username"`
	Email        string `db:"email"`
	PasswordHash string `db:"password_hash"`
	CreatedAt    string `db:"created_at"`
	Role         string `db:"user_role"`
}
