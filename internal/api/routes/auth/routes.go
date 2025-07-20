package auth

import (
	"net/http"
	"time"

	"github.com/akramboussanni/gocode/internal/api/routes/auth/authhandler"
	"github.com/akramboussanni/gocode/internal/log"
	"github.com/akramboussanni/gocode/internal/middleware"
	"github.com/akramboussanni/gocode/internal/repo"
	"github.com/go-chi/chi/v5"
)

func NewAuthRouter(userRepo *repo.UserRepo, tokenRepo *repo.TokenRepo, lockoutRepo *repo.LockoutRepo, logger log.Logger) http.Handler {
	ar := &authhandler.AuthRouter{UserRepo: userRepo, TokenRepo: tokenRepo, LockoutRepo: lockoutRepo, Logger: logger}
	r := chi.NewRouter()

	r.Use(middleware.MaxBytesMiddleware(1 << 20))

	//8/min+recaptcha
	r.Group(func(r chi.Router) {
		middleware.AddRatelimit(r, 7, 1*time.Minute)
		middleware.AddRecaptcha(r)
		r.Post("/login", ar.HandleLogin)
		r.Post("/logout", ar.HandleLogout)
		r.Post("/logout-all", ar.HandleLogoutEverywhere)
	})

	//15/hour+recaptcha
	r.Group(func(r chi.Router) {
		middleware.AddRatelimit(r, 15, 1*time.Hour)
		middleware.AddRecaptcha(r)
		r.Post("/reset-password", ar.HandleForgotPassword)
		r.Post("/forgot-password", ar.HandleSendForgotPassword)
		r.Post("/confirm-email", ar.HandleConfirmEmail)
		r.Post("/resend-confirmation", ar.HandleResendConfirmation)
		r.Post("/register", ar.HandleRegister)
	})

	//8/hour+auth+recaptcha
	r.Group(func(r chi.Router) {
		middleware.AddRatelimit(r, 8, 1*time.Hour)
		middleware.AddAuth(r, ar.UserRepo, ar.TokenRepo)
		middleware.AddRecaptcha(r)
		r.Post("/change-password", ar.HandleChangePassword)
	})

	//30/min+auth
	r.Group(func(r chi.Router) {
		middleware.AddRatelimit(r, 30, 1*time.Minute)
		middleware.AddAuth(r, ar.UserRepo, ar.TokenRepo)
		r.Get("/me", ar.HandleProfile)
	})

	//15/min
	r.Group(func(r chi.Router) {
		middleware.AddRatelimit(r, 15, 1*time.Minute)
		r.Post("/refresh", ar.HandleRefresh)
	})

	return r
}
