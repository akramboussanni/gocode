package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/jwt"
	"github.com/akramboussanni/gocode/internal/mailer"
	"github.com/akramboussanni/gocode/internal/model"
	"github.com/akramboussanni/gocode/internal/utils"

	"github.com/google/uuid"
)

func (ar *AuthRouter) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var cred Credentials

	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if cred.Username == "" || cred.Email == "" || cred.Password == "" {
		http.Error(w, "invalid credentials", http.StatusBadRequest)
		return
	}

	if strings.Contains(cred.Username, "@") || !utils.IsValidEmail(cred.Email) || !utils.IsValidPassword(cred.Password) {
		http.Error(w, "invalid credentials", http.StatusBadRequest)
		return
	}

	duplicate, err := ar.UserRepo.DuplicateName(r.Context(), cred.Username)
	if err != nil {
		http.Error(w, "server error dupe", http.StatusInternalServerError)
		return
	}

	if duplicate {
		http.Error(w, "invalid credentials", http.StatusBadRequest)
		return
	}

	hash, err := utils.HashPassword(cred.Password)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	confirmToken, err := utils.GetRandomToken(16)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	user := &model.User{ID: utils.GenerateID(), Username: cred.Username, PasswordHash: hash, Email: cred.Email, CreatedAt: time.Now().UTC().Unix(), Role: "user", EmailConfirmed: false, EmailConfirmToken: confirmToken.Hash, EmailConfirmIssuedAt: time.Now().UTC().Unix()}

	headers := []mailer.MailHeader{
		mailer.MakeHeader("Subject", "Email confirmation"),
		mailer.MakeHeader("To", cred.Email),
	}

	if err = mailer.Send("confirmregister", headers, map[string]any{"Token": confirmToken.Raw}); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	if err := ar.UserRepo.CreateUser(r.Context(), user); err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	api.WriteJSON(w, 200, map[string]string{"message": "user created"})
}

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
	api.WriteJSON(w, 200, resp)
}
