package middleware

import (
	"net/http"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/model"
	"github.com/google/go-querystring/query"
)

func ValidateRecaptcha(w http.ResponseWriter, r *http.Request) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-Recaptcha-Token")
			if token == "" {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}

			req := model.RecaptchaVerificationPayload{
				Secret:   config.RecaptchaSecret,
				Response: token,
				RemoteIP: r.RemoteAddr,
			}

			values, err := query.Values(req)
			if err != nil {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}

			resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", values)

			if err != nil {
				http.Error(w, "Recaptcha verification failed", http.StatusInternalServerError)
				return
			}

			defer resp.Body.Close()
		})
	}
}

func validateRecaptcha()
