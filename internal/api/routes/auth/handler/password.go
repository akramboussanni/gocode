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

// @Summary Reset password with token
// @Description Reset user password using a reset token sent via email. Token expires after 1 hour. New password must meet security requirements.
// @Tags Password Management
// @Accept json
// @Produce json
// @Param request body PasswordResetRequest true "Reset token and new password"
// @Success 200 {string} string "Password reset successful"
// @Failure 400 {object} api.ErrorResponse "Invalid password format or requirements not met"
// @Failure 401 {object} api.ErrorResponse "Invalid or expired reset token"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (5 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error"
// @Router /api/auth/reset-password [post]
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

// @Summary Request password reset email
// @Description Send password reset email to user's email address. A reset token will be generated and sent via email with a 1-hour expiration.
// @Tags Password Management
// @Accept json
// @Produce json
// @Param request body EmailRequest true "User email and reset URL"
// @Success 200 {object} api.SuccessResponse "Password reset email sent successfully"
// @Failure 400 {object} api.ErrorResponse "Invalid request format or missing email"
// @Failure 401 {object} api.ErrorResponse "User not found with provided email"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (5 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error or email sending failure"
// @Router /api/auth/forgot-password [post]
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

	token, err := GenerateTokenAndSendEmail(user.Email, "forgotpassword", "Password reset", req.Url)
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

// @Summary Change password (authenticated)
// @Description Change user password while authenticated. Requires current password verification and new password must meet security requirements.
// @Tags Password Management
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body PasswordChangeRequest true "Current password and new password"
// @Success 200 {string} string "Password changed successfully"
// @Failure 400 {object} api.ErrorResponse "Invalid password format or requirements not met"
// @Failure 401 {object} api.ErrorResponse "Unauthorized or incorrect current password"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (5 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error"
// @Router /api/auth/change-password [post]
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
