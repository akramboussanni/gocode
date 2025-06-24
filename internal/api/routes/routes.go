package routes

import (
	"net/http"

	"github.com/akramboussanni/gocode/internal/api/routes/auth"
	"github.com/akramboussanni/gocode/internal/repo"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func SetupRouter(repos *repo.Repos) http.Handler {
	r := chi.NewRouter()

	// Middleware stack
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Routes
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("github.com/akramboussanni/gocode"))
	})

	r.Mount("/api/auth", auth.NewAuthRouter(repos.User, repos.Token))

	return r
}
