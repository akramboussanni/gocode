// this file contains translations
package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/jwt"
	"github.com/akramboussanni/gocode/internal/mailer"
	"github.com/akramboussanni/gocode/internal/middleware"
	"github.com/akramboussanni/gocode/internal/model"
	"github.com/akramboussanni/gocode/internal/repo"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/google/uuid"
)

type AuthRouter struct {
	userRepo  *repo.UserRepo
	tokenRepo *repo.TokenRepo
}

func NewAuthRouter(userRepo *repo.UserRepo, tokenRepo *repo.TokenRepo) http.Handler {
	ar := &AuthRouter{userRepo: userRepo, tokenRepo: tokenRepo}
	r := chi.NewRouter()

	r.Use(maxBytesMiddleware(1 << 20))

	//10/min
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(10, 1*time.Minute))
		r.Post("/register", ar.handleRegister)
		r.Post("/login", ar.handleLogin)
		r.Post("/logout", ar.handleLogout)
	})

	//30/min
	r.Group(func(r chi.Router) {
		r.Use(ar.authMiddleware)
		r.Use(httprate.LimitByIP(30, 1*time.Minute))
		r.Get("/me", ar.handleProfile)
	})

	//5/min
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(5, 1*time.Minute))
		r.Post("/confirm-email", ar.handleConfirmEmail)
	})

	return r
}
func (ar *AuthRouter) handleRegister(w http.ResponseWriter, r *http.Request) {
	var cred Credentials

	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if cred.Username == "" || cred.Email == "" || cred.Password == "" {
		http.Error(w, "invalid credentials", http.StatusBadRequest)
		return
	}

	if strings.Contains(cred.Username, "@") || !IsValidEmail(cred.Email) || !IsValidPassword(cred.Password) {
		http.Error(w, "invalid credentials", http.StatusBadRequest)
		return
	}

	duplicate, err := ar.userRepo.DuplicateName(r.Context(), cred.Username)
	if err != nil {
		http.Error(w, "server error dupe", http.StatusInternalServerError)
		return
	}

	if duplicate {
		http.Error(w, "invalid credentials", http.StatusBadRequest)
		return
	}

	hash, err := HashPassword(cred.Password)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	confirmToken, err := GetRandomToken(16)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	user := &model.User{ID: GenerateID(), Username: cred.Username, PasswordHash: hash, Email: cred.Email, CreatedAt: time.Now().UTC().Unix(), Role: "user", EmailConfirmed: false, EmailConfirmToken: confirmToken.Hash, EmailConfirmIssuedAt: time.Now().UTC().Unix()}

	headers := []mailer.MailHeader{
		mailer.MakeHeader("Subject", "Email confirmation"),
		mailer.MakeHeader("To", cred.Email),
	}

	mailer.Send("confirmregister", headers, map[string]any{"Token": confirmToken.Hash})

	if err := ar.userRepo.CreateUser(r.Context(), user); err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, 200, map[string]string{"message": "user created"})
}

func (ar *AuthRouter) handleLogin(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	user, err := ar.userRepo.GetUserByEmail(r.Context(), cred.Email)
	if err != nil || user == nil {
		log.Println(err)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if !ComparePassword(user.PasswordHash, cred.Password) || !user.EmailConfirmed {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	now := time.Now().Unix()
	exp := now + 7*24*3600 //7d

	claims := jwt.Claims{
		UserID:     user.ID,
		TokenID:    uuid.New().String(),
		IssuedAt:   now,
		Expiration: exp,
		Email:      user.Email,
		Role:       user.Role,
	}

	token := jwt.Jwt{
		Header: jwt.JwtHeader{
			Algorithm: "HS256",
			Type:      "JWT",
		},
		Payload: claims,
	}

	tokenStr := token.GenerateToken()

	resp := map[string]string{"token": tokenStr}
	writeJSON(w, 200, resp)
}

func (ar *AuthRouter) handleProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	user, err := ar.userRepo.GetUserById(r.Context(), userID)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// temporary solution that will later be recoded
	response := struct {
		ID        int64  `json:"id"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		CreatedAt int64  `json:"created_at"`
		Role      string `json:"role"`
	}{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		Role:      user.Role,
	}

	writeJSON(w, 200, response)
}

func (ar *AuthRouter) handleLogout(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(w, r, config.JwtSecret, ar.tokenRepo)
	if claims == nil {
		return
	}

	expiration := time.Unix(claims.Expiration, 0)

	err := ar.tokenRepo.RevokeToken(r.Context(), model.JwtBlacklist{
		TokenID:   claims.TokenID,
		UserID:    claims.UserID,
		ExpiresAt: expiration.UTC().Unix(),
	})
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (ar *AuthRouter) handleConfirmEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	sha := sha256.Sum256([]byte(token))
	hash := base64.RawURLEncoding.EncodeToString(sha[:])
	user, err := ar.userRepo.GetUserByTokenHash(r.Context(), hash)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if user.EmailConfirmed { // this scenario should not happen. normally
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	expiry := user.EmailConfirmIssuedAt + 3600*24 //24h expiry
	if expiry < time.Now().UTC().Unix() {
		http.Error(w, "expired token, please request a new one.", http.StatusUnauthorized)
		return
	}

	if err = ar.userRepo.MarkUserConfirmed(r.Context(), user.ID); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (ar *AuthRouter) authMiddleware(next http.Handler) http.Handler {
	return middleware.JWTAuth(config.JwtSecret, ar.tokenRepo)(next)
}

func maxBytesMiddleware(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
