package handler

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/model"
	"github.com/akramboussanni/gocode/internal/utils"
)

// @Summary Register new user
// @Description Register a new user account with email confirmation
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body Credentials true "User registration credentials"
// @Success 200 {object} map[string]string "User created successfully"
// @Failure 400 {string} string "Invalid credentials or duplicate username"
// @Failure 500 {string} string "Server error"
// @Router /api/auth/register [post]
func (ar *AuthRouter) HandleRegister(w http.ResponseWriter, r *http.Request) {
	cred, err := api.DecodeJSON[Credentials](w, r)
	if err != nil {
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
		api.WriteInternalError(w)
		return
	}

	if duplicate {
		http.Error(w, "invalid credentials", http.StatusBadRequest)
		return
	}

	hash, err := utils.HashPassword(cred.Password)
	if err != nil {
		api.WriteInternalError(w)
		return
	}

	user := &model.User{ID: utils.GenerateID(), Username: cred.Username, PasswordHash: hash, Email: cred.Email, CreatedAt: time.Now().UTC().Unix(), Role: "user", EmailConfirmed: false}

	if err := ar.UserRepo.CreateUser(r.Context(), user); err != nil {
		log.Println(err)
		api.WriteInternalError(w)
		return
	}

	token, err := GenerateTokenAndSendEmail(user.Email, "confirmregister", "Email confirmation")
	if err != nil {
		api.WriteInternalError(w)
		return
	}

	if err := ar.UserRepo.AssignUserConfirmToken(r.Context(), token.Hash, time.Now().UTC().Unix(), user.ID); err != nil {
		api.WriteInternalError(w)
		return
	}

	api.WriteMessage(w, 200, "message", "user created")
}
