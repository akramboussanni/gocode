package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/model"
	"github.com/akramboussanni/gocode/internal/utils"
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
		http.Error(w, "server error", http.StatusInternalServerError)
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

	user := &model.User{ID: utils.GenerateID(), Username: cred.Username, PasswordHash: hash, Email: cred.Email, CreatedAt: time.Now().UTC().Unix(), Role: "user", EmailConfirmed: false}

	if err := ar.UserRepo.CreateUser(r.Context(), user); err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	_, hash, err = GenerateTokenAndSendEmail(user.Email, "confirmregister", "Email confirmation")
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	user.EmailConfirmToken = hash
	user.EmailConfirmIssuedAt = time.Now().UTC().Unix()
	if err := ar.UserRepo.UpdateUser(r.Context(), user); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	api.WriteJSON(w, 200, map[string]string{"message": "user created"})
}
