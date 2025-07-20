// this file contains translations
package authhandler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/model"
	"github.com/akramboussanni/gocode/internal/utils"
)

// shared helper for password change logic
func (ar *AuthRouter) changeUserPassword(ctx context.Context, w http.ResponseWriter, user *model.User, newPassword, ip string) bool {
	if !utils.IsValidPassword(newPassword) {
		ar.Logger.Warn("Invalid new password format", "userID:", user.ID)
		api.WriteMessage(w, 400, "error", "invalid password")
		return false
	}
	if utils.ComparePassword(user.PasswordHash, newPassword) {
		ar.Logger.Error("Same password")
		api.WriteMessage(w, 400, "error", "same password")
		return false
	}
	hash, err := utils.HashPassword(newPassword)
	if err != nil {
		ar.Logger.Error("Failed to hash new password:", err)
		api.WriteInternalError(w)
		return false
	}
	if err := ar.UserRepo.ChangeUserPassword(ctx, hash, user.ID); err != nil {
		ar.Logger.Error("Failed to change user password:", err)
		api.WriteInternalError(w)
		return false
	}
	if err := ar.UserRepo.IncrementJwtSessionID(ctx, user.ID); err != nil {
		ar.Logger.Error("Failed to revoke all sessions:", err)
		api.WriteInternalError(w)
		return false
	}
	if err := ar.LockoutRepo.UnlockAccount(ctx, user.ID, ip); err != nil {
		ar.Logger.Error("Failed to revoke all sessions:", err)
		api.WriteInternalError(w)
		return false
	}
	ar.Logger.Info("Password changed successfully", "userID:", user.ID)
	return true
}

// @Summary Reset password with token
// @Description Reset user password using a reset token sent via email. Token expires after 1 hour. New password must meet security requirements.
// @Tags Password Management
// @Accept json
// @Produce json
// @Param X-Recaptcha-Token header string false "reCAPTCHA verification token (optional if reCAPTCHA is not configured)"
// @Param request body PasswordResetRequest true "Reset token and new password"
// @Success 200 {string} string "Password reset successful"
// @Failure 400 {object} api.ErrorResponse "Invalid password format or requirements not met"
// @Failure 401 {object} api.ErrorResponse "Invalid or expired reset token"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (5 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error"
// @Router /api/auth/reset-password [post]
func (ar *AuthRouter) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	ar.Logger.Info("HandleForgotPassword called")
	req, err := api.DecodeJSON[PasswordResetRequest](w, r)
	if err != nil {
		ar.Logger.Error("Failed to decode password reset request:", err)
		return
	}

	b, err := base64.URLEncoding.DecodeString(req.Token)
	if err != nil {
		ar.Logger.Error("Failed to decode reset token:", err)
		api.WriteInternalError(w)
		return
	}

	sha := sha256.Sum256(b)
	tokenHash := base64.URLEncoding.EncodeToString(sha[:])
	user, err := ar.UserRepo.GetUserByResetToken(r.Context(), tokenHash)
	if err != nil {
		ar.Logger.Warn("Invalid or expired reset token", "tokenHash:", tokenHash)
		api.WriteInvalidCredentials(w)
		return
	}

	expiry := user.PasswordResetIssuedAt + config.ForgotPasswordExpiry
	if expiry < time.Now().UTC().Unix() {
		ar.Logger.Warn("Expired password reset token", "userID:", user.ID)
		http.Error(w, "expired token, please request a new one", http.StatusUnauthorized)
		return
	}

	if !ar.changeUserPassword(r.Context(), w, user, req.NewPassword, utils.GetClientIP(r)) {
		return
	}

	w.WriteHeader(http.StatusOK)
}

// @Summary Request password reset email
// @Description Send password reset email to user's email address. A reset token will be generated and sent via email with a 1-hour expiration.
// @Tags Password Management
// @Accept json
// @Produce json
// @Param X-Recaptcha-Token header string false "reCAPTCHA verification token (optional if reCAPTCHA is not configured)"
// @Param request body EmailRequest true "User email and reset URL"
// @Success 200 {object} api.SuccessResponse "Password reset email sent successfully"
// @Failure 400 {object} api.ErrorResponse "Invalid request format or missing email"
// @Failure 401 {object} api.ErrorResponse "User not found with provided email"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (5 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error or email sending failure"
// @Router /api/auth/forgot-password [post]
func (ar *AuthRouter) HandleSendForgotPassword(w http.ResponseWriter, r *http.Request) {
	ar.Logger.Info("HandleSendForgotPassword called")
	req, err := api.DecodeJSON[EmailRequest](w, r)
	if err != nil {
		ar.Logger.Error("Failed to decode forgot password request:", err)
		return
	}

	user, err := ar.UserRepo.GetUserByEmail(r.Context(), req.Email)
	if err != nil || user == nil {
		ar.Logger.Warn("Forgot password: user not found", "email:", req.Email)
		api.WriteInvalidCredentials(w)
		return
	}

	token, err := GenerateTokenAndSendEmail(user.Email, "forgotpassword", "Password reset", req.Url)
	if err != nil {
		ar.Logger.Error("Failed to send password reset email:", err)
		api.WriteInternalError(w)
		return
	}

	if err := ar.UserRepo.AssignUserResetToken(r.Context(), token.Hash, time.Now().UTC().Unix(), user.ID); err != nil {
		ar.Logger.Error("Failed to assign reset token:", err)
		api.WriteInternalError(w)
		return
	}

	ar.Logger.Info("Password reset email sent", "userID:", user.ID, "email:", user.Email)
	api.WriteMessage(w, 200, "message", "password reset sent")
}

// @Summary Change password (authenticated)
// @Description Change user password while authenticated. Requires current password verification and new password must meet security requirements.
// @Tags Password Management
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer JWT token" default(Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)
// @Param request body PasswordChangeRequest true "Current password and new password"
// @Success 200 {string} string "Password changed successfully"
// @Failure 400 {object} api.ErrorResponse "Invalid password format or requirements not met"
// @Failure 401 {object} api.ErrorResponse "Unauthorized or incorrect current password"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (5 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error"
// @Router /api/auth/change-password [post]
func (ar *AuthRouter) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	ar.Logger.Info("HandleChangePassword called")
	req, err := api.DecodeJSON[PasswordChangeRequest](w, r)
	if err != nil {
		ar.Logger.Error("Failed to decode change password request:", err)
		return
	}

	user, ok := utils.UserFromContext(r.Context())
	if !ok {
		ar.Logger.Error("Failed to get user from context")
		return
	}

	if !utils.ComparePassword(user.PasswordHash, req.OldPassword) {
		ar.Logger.Warn("Incorrect current password", "userID:", user.ID)
		api.WriteInvalidCredentials(w)
		return
	}

	if !ar.changeUserPassword(r.Context(), w, user, req.NewPassword, utils.GetClientIP(r)) {
		return
	}

	w.WriteHeader(http.StatusOK)
}
