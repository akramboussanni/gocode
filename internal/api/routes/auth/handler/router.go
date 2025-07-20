package handler

import (
	"github.com/akramboussanni/gocode/internal/repo"
)

type AuthRouter struct {
	UserRepo  *repo.UserRepo
	TokenRepo *repo.TokenRepo
}
