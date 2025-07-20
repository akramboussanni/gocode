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

// @Summary Register new user account
// @Description Register a new user account with email confirmation. The system will validate credentials, check for duplicates, hash the password, and send a confirmation email. Username cannot contain '@' symbol.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "User registration credentials including confirmation URL"
// @Success 200 {object} api.SuccessResponse "User account created successfully - confirmation email sent"
// @Failure 400 {object} api.ErrorResponse "Invalid credentials, duplicate username, or validation errors"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (2 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error or email sending failure"
// @Router /api/auth/register [post]
func (ar *AuthRouter) HandleRegister(w http.ResponseWriter, r *http.Request) {
	cred, err := api.DecodeJSON[RegisterRequest](w, r)
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

	token, err := GenerateTokenAndSendEmail(user.Email, "confirmregister", "Email confirmation", cred.Url)
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
