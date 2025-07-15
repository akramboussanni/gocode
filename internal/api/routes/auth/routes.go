package auth

import (
	"encoding/json"
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

	//10/min
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(10, 1*time.Minute))
		r.Post("/register", ar.HandleRegister)
		r.Post("/login", ar.HandleLogin)
		r.Post("/logout", ar.HandleLogout)
	})

	//30/min
	r.Group(func(r chi.Router) {
		r.Use(ar.AuthMiddleware)
		r.Use(httprate.LimitByIP(30, 1*time.Minute))
		r.Get("/me", ar.HandleProfile)
	})

	//5/min
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(5, 1*time.Minute))
		r.Post("/confirm-email", ar.HandleConfirmEmail)
		r.Post("/resend-confirmation", ar.HandleResendConfirmation)
	})

	return r
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
