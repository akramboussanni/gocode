package auth

import (
	"net/http"
	"time"

	"github.com/akramboussanni/gocode/internal/api/routes/auth/handler"
	"github.com/akramboussanni/gocode/internal/middleware"
	"github.com/akramboussanni/gocode/internal/repo"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
)

func NewAuthRouter(userRepo *repo.UserRepo, tokenRepo *repo.TokenRepo) http.Handler {
	ar := &handler.AuthRouter{UserRepo: userRepo, TokenRepo: tokenRepo}
	r := chi.NewRouter()

	r.Use(middleware.MaxBytesMiddleware(1 << 20))

	//8/min
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(8, 1*time.Minute))
		middleware.AddRecaptcha(r)
		r.Post("/login", ar.HandleLogin)
		r.Post("/logout", ar.HandleLogout)
	})

	//2/min
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(2, 1*time.Minute))
		middleware.AddRecaptcha(r)
		r.Post("/register", ar.HandleRegister)

	})

	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(8, 1*time.Minute))
		middleware.AddRecaptcha(r)
		r.Post("/refresh", ar.HandleRefresh)
	})

	//30/min
	r.Group(func(r chi.Router) {
		middleware.AddAuth(r, ar.TokenRepo)
		r.Use(httprate.LimitByIP(30, 1*time.Minute))
		r.Get("/me", ar.HandleProfile)
	})

	//5/min
	r.Group(func(r chi.Router) {
		middleware.AddRecaptcha(r)
		r.Use(httprate.LimitByIP(5, 1*time.Minute))
		r.Post("/confirm-email", ar.HandleConfirmEmail)
		r.Post("/resend-confirmation", ar.HandleResendConfirmation)
		r.Post("/reset-password", ar.HandleForgotPassword)
		r.Post("/forgot-password", ar.HandleSendForgotPassword)
		r.Post("/change-password", ar.HandleChangePassword)
	})

	return r
}
