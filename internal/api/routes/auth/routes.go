package auth

import (
	"net/http"
	"time"

	"github.com/akramboussanni/gocode/internal/api/routes/auth/authhandler"
	"github.com/akramboussanni/gocode/internal/middleware"
	"github.com/akramboussanni/gocode/internal/repo"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
)

func NewAuthRouter(userRepo *repo.UserRepo, tokenRepo *repo.TokenRepo, lockoutRepo *repo.LockoutRepo) http.Handler {
	ar := &authhandler.AuthRouter{UserRepo: userRepo, TokenRepo: tokenRepo, LockoutRepo: lockoutRepo}
	r := chi.NewRouter()

	r.Use(middleware.MaxBytesMiddleware(1 << 20))

	//8/min+recaptcha
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(8, 1*time.Minute))
		middleware.AddRecaptcha(r)
		r.Post("/login", ar.HandleLogin)
		r.Post("/logout", ar.HandleLogout)
		r.Post("/logout-all", ar.HandleLogoutEverywhere)
	})

	//2/min+recaptcha
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(2, 1*time.Minute))
		middleware.AddRecaptcha(r)
		r.Post("/register", ar.HandleRegister)
		r.Post("/refresh", ar.HandleRefresh)
	})

	//30/min+auth+recaptcha
	r.Group(func(r chi.Router) {
		middleware.AddAuth(r, ar.UserRepo, ar.TokenRepo)
		r.Use(httprate.LimitByIP(30, 1*time.Minute))
		r.Get("/me", ar.HandleProfile)
	})

	//8/min+auth+recaptcha
	r.Group(func(r chi.Router) {
		middleware.AddRecaptcha(r)
		middleware.AddAuth(r, ar.UserRepo, ar.TokenRepo)
		r.Use(httprate.LimitByIP(8, 1*time.Minute))
		r.Post("/change-password", ar.HandleChangePassword)
	})

	//5/min+recaptcha
	r.Group(func(r chi.Router) {
		middleware.AddRecaptcha(r)
		r.Use(httprate.LimitByIP(5, 1*time.Minute))
		r.Post("/reset-password", ar.HandleForgotPassword)
		r.Post("/forgot-password", ar.HandleSendForgotPassword)
		r.Post("/confirm-email", ar.HandleConfirmEmail)
		r.Post("/resend-confirmation", ar.HandleResendConfirmation)
	})

	return r
}
