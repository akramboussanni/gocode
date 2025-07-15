package handler

import (
	"net/http"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/middleware"
	"github.com/akramboussanni/gocode/internal/repo"
)

type AuthRouter struct {
	UserRepo  *repo.UserRepo
	TokenRepo *repo.TokenRepo
}

func (ar *AuthRouter) AuthMiddleware(next http.Handler) http.Handler {
	return middleware.JWTAuth(config.JwtSecret, ar.TokenRepo)(next)
}
