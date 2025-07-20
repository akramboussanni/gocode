package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/jwt"
	"github.com/akramboussanni/gocode/internal/repo"
)

type contextKey string

const userIDKey contextKey = "userID"

func UserIDFromContext(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(userIDKey).(int64)
	return id, ok
}

func JWTAuth(secret []byte, tr *repo.TokenRepo, expectedType jwt.TokenType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(w, r, secret, tr, expectedType)
			if claims == nil {
				return
			}

			ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetClaims(w http.ResponseWriter, r *http.Request, secret []byte, tr *repo.TokenRepo, expectedType jwt.TokenType) *jwt.Claims {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "missing or invalid authorization header", http.StatusUnauthorized)
		return nil
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := jwt.ValidateToken(tokenStr, config.JwtSecret, tr)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return nil
	}

	if claims.Type != expectedType {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return nil
	}

	return claims
}
