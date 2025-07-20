package authhandler

import (
	"github.com/akramboussanni/gocode/internal/log"
	"github.com/akramboussanni/gocode/internal/repo"
)

type AuthRouter struct {
	UserRepo    *repo.UserRepo
	TokenRepo   *repo.TokenRepo
	LockoutRepo *repo.LockoutRepo
	Logger      log.Logger
}
