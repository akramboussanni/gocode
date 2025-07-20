package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/jwt"
	"github.com/akramboussanni/gocode/internal/utils"
	"github.com/google/uuid"
)

func (ar *AuthRouter) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	user, err := ar.UserRepo.GetUserByEmail(r.Context(), cred.Email)
	if err != nil || user == nil {
		log.Println(err)
		http.Error(w, "invalid credentials email", http.StatusUnauthorized)
		return
	}

	if !utils.ComparePassword(user.PasswordHash, cred.Password) || !user.EmailConfirmed {
		http.Error(w, "invalid credentials pass", http.StatusUnauthorized)
		return
	}

	now := time.Now().Unix()
	claims := jwt.Claims{
		UserID:   user.ID,
		TokenID:  uuid.New().String(),
		IssuedAt: now,
		Email:    user.Email,
		Role:     user.Role,
	}

	token := jwt.CreateJwt(claims)
	sessionToken := token.WithType(jwt.Credentials).GenerateToken()
	refreshToken := token.WithType(jwt.Refresh).GenerateToken()

	resp := LoginResponse{Session: sessionToken, Refresh: refreshToken}
	api.WriteJSON(w, 200, resp)
}

func (ar *AuthRouter) HandleRenew(w http.ResponseWriter, r *http.Request) {

}
