package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/ctxutil"
	"github.com/akramboussanni/gocode/internal/jwt"
	"github.com/akramboussanni/gocode/internal/repo"
	"github.com/go-chi/chi/v5"
)

func AddAuth(r chi.Router, tr *repo.TokenRepo) {
	r.Use(func(next http.Handler) http.Handler {
		return JWTAuth(config.JwtSecret, tr, jwt.Credentials)(next)
	})
}

func JWTAuth(secret []byte, tr *repo.TokenRepo, expectedType jwt.TokenType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaimsFromHeader(w, r, secret, tr)
			if claims == nil {
				return
			}

			if claims.Type != expectedType {
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ctxutil.UserIDKey, claims.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetClaimsFromHeader(w http.ResponseWriter, r *http.Request, secret []byte, tr *repo.TokenRepo) *jwt.Claims {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "missing or invalid authorization header", http.StatusUnauthorized)
		return nil
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	return GetClaims(w, r, tokenStr, secret, tr)
}

func GetClaims(w http.ResponseWriter, r *http.Request, token string, secret []byte, tr *repo.TokenRepo) *jwt.Claims {
	claims, err := jwt.ValidateToken(token, config.JwtSecret, tr)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return nil
	}

	return claims
}
