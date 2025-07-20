package model

type FailedLogin struct {
	ID          int    `db:"id"`
	UserID      int64  `db:"user_id"`
	IPAddress   string `db:"ip_address"`
	AttemptedAt int64  `db:"attempted_at"`
}

type Lockout struct {
	ID          int    `db:"id"`
	UserID      int64  `db:"user_id"`
	IPAddress   string `db:"ip_address"`
	LockedUntil int64  `db:"locked_until"`
	Reason      string `db:"reason"`
	CreatedAt   int64  `db:"created_at"`
}
