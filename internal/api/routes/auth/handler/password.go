// this file contains translations
package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/ctxutil"
	"github.com/akramboussanni/gocode/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

func (ar *AuthRouter) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	req, err := api.DecodeJSON[PasswordResetRequest](w, r)
	if err != nil {
		return
	}

	b, err := base64.URLEncoding.DecodeString(req.Token)
	if err != nil {
		api.WriteInternalError(w)
		return
	}

	sha := sha256.Sum256(b)
	tokenHash := base64.URLEncoding.EncodeToString(sha[:])
	user, err := ar.UserRepo.GetUserByResetToken(r.Context(), tokenHash)
	if err != nil {
		api.WriteInvalidCredentials(w)
		return
	}

	expiry := user.PasswordResetIssuedAt + 3600 //1h expiry
	if expiry < time.Now().UTC().Unix() {
		http.Error(w, "expired token, please request a new one", http.StatusUnauthorized)
		return
	}

	if !utils.IsValidPassword(req.NewPassword) {
		http.Error(w, "invalid password", http.StatusBadRequest)
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		api.WriteInternalError(w)
		return
	}

	if err = ar.UserRepo.ChangeUserPassword(r.Context(), string(passwordHash), user.ID); err != nil {
		api.WriteInternalError(w)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (ar *AuthRouter) HandleSendForgotPassword(w http.ResponseWriter, r *http.Request) {
	req, err := api.DecodeJSON[EmailRequest](w, r)
	if err != nil {
		return
	}

	user, err := ar.UserRepo.GetUserByEmail(r.Context(), req.Email)
	if err != nil || user == nil {
		api.WriteInvalidCredentials(w)
		return
	}

	token, err := GenerateTokenAndSendEmail(user.Email, "forgotpassword", "Password reset")
	if err != nil {
		api.WriteInternalError(w)
		return
	}

	if err := ar.UserRepo.AssignUserResetToken(r.Context(), token.Hash, time.Now().UTC().Unix(), user.ID); err != nil {
		api.WriteInternalError(w)
		return
	}

	api.WriteMessage(w, 200, "message", "password reset sent")
}

func (ar *AuthRouter) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	req, err := api.DecodeJSON[PasswordChangeRequest](w, r)
	if err != nil {
		return
	}

	user := ctxutil.FetchUserWithContext(r.Context(), w, ar.UserRepo.GetUserById)
	if user == nil {
		return
	}

	if !utils.IsValidPassword(req.NewPassword) {
		http.Error(w, "invalid password", http.StatusBadRequest)
		return
	}

	if !utils.ComparePassword(req.OldPassword, user.PasswordHash) {
		api.WriteInvalidCredentials(w)
		return
	}

	hash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		api.WriteInternalError(w)
		return
	}

	err = ar.UserRepo.ChangeUserPassword(r.Context(), hash, user.ID)
	if err != nil {
		api.WriteInternalError(w)
		return
	}

	w.WriteHeader(http.StatusOK)
}
