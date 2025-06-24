package repo

import (
	"github.com/jmoiron/sqlx"
)

type Repos struct {
	User  *UserRepo
	Role  *RoleRepo
	Token *TokenRepo
	// Add other repos here
}

func NewRepos(db *sqlx.DB) *Repos {
	return &Repos{
		User:  NewUserRepo(db),
		Role:  NewRoleRepo(db),
		Token: NewTokenRepo(db),
	}
}
