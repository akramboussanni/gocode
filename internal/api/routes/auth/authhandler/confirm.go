// this file contains translations
package authhandler

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/utils"
)

// @Summary Confirm email address
// @Description Confirm user's email address using the confirmation token sent during registration. Token expires after 24 hours.
// @Tags Email Verification
// @Accept json
// @Produce json
// @Param X-Recaptcha-Token header string false "reCAPTCHA verification token (optional if reCAPTCHA is not configured)"
// @Param request body TokenRequest true "Email confirmation token"
// @Success 200 {object} api.SuccessResponse "Email confirmed successfully - user can now login"
// @Failure 400 {object} api.ErrorResponse "Invalid request format or missing token"
// @Failure 401 {object} api.ErrorResponse "Invalid or expired confirmation token"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (5 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error"
// @Router /api/auth/confirm-email [post]
func (ar *AuthRouter) HandleConfirmEmail(w http.ResponseWriter, r *http.Request) {
	ar.Logger.Info("HandleConfirmEmail called")
	req, err := api.DecodeJSON[TokenRequest](w, r)
	if err != nil {
		ar.Logger.Error("Failed to decode confirm email request:", err)
		return
	}

	b, err := base64.URLEncoding.DecodeString(req.Token)
	if err != nil {
		ar.Logger.Error("Failed to decode confirmation token:", err)
		api.WriteInternalError(w)
		return
	}

	sha := sha256.Sum256(b)
	hash := base64.URLEncoding.EncodeToString(sha[:])
	user, err := ar.UserRepo.GetUserByConfirmationToken(r.Context(), hash)
	if err != nil {
		ar.Logger.Warn("Invalid or expired confirmation token", "tokenHash:", hash)
		api.WriteInvalidCredentials(w)
		return
	}

	if user.EmailConfirmed {
		ar.Logger.Warn("Email already confirmed", "userID:", user.ID)
		api.WriteInvalidCredentials(w)
		return
	}

	expiry := user.EmailConfirmIssuedAt + config.EmailConfirmExpiry
	if expiry < time.Now().UTC().Unix() {
		ar.Logger.Warn("Expired confirmation token", "userID:", user.ID)
		http.Error(w, "expired token, please request a new one", http.StatusUnauthorized)
		return
	}

	if err = ar.UserRepo.MarkUserConfirmed(r.Context(), user.ID); err != nil {
		ar.Logger.Error("Failed to mark user confirmed:", err)
		api.WriteInternalError(w)
		return
	}

	ar.Logger.Info("Email confirmed successfully", "userID:", user.ID)
	w.WriteHeader(http.StatusOK)
}

// @Summary Resend email confirmation
// @Description Resend email confirmation token to user's email address. Useful if the original confirmation email was not received or expired.
// @Tags Email Verification
// @Accept json
// @Produce json
// @Param X-Recaptcha-Token header string false "reCAPTCHA verification token (optional if reCAPTCHA is not configured)"
// @Param request body EmailRequest true "User email and confirmation URL"
// @Success 200 {object} api.SuccessResponse "Confirmation email sent successfully"
// @Failure 400 {object} api.ErrorResponse "Invalid request format or missing email"
// @Failure 401 {object} api.ErrorResponse "User not found or email already confirmed"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (5 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error or email sending failure"
// @Router /api/auth/resend-confirmation [post]
func (ar *AuthRouter) HandleResendConfirmation(w http.ResponseWriter, r *http.Request) {
	ar.Logger.Info("HandleResendConfirmation called")
	req, err := api.DecodeJSON[EmailRequest](w, r)
	if err != nil {
		ar.Logger.Error("Failed to decode resend confirmation request:", err)
		return
	}

	user, err := ar.UserRepo.GetUserByEmail(r.Context(), req.Email)
	if err != nil || user == nil {
		ar.Logger.Warn("Resend confirmation: user not found", "email:", req.Email)
		api.WriteInvalidCredentials(w)
		return
	}

	if user.EmailConfirmed {
		ar.Logger.Warn("Email already confirmed for resend", "userID:", user.ID)
		http.Error(w, "email already confirmed", http.StatusBadRequest)
		return
	}

	expiryStr := utils.ExpiryToString(24 * 3600)
	token, err := GenerateTokenAndSendEmail(user.Email, "confirmregister", "Email confirmation", req.Url, expiryStr)
	if err != nil {
		ar.Logger.Error("Failed to send confirmation email:", err)
		api.WriteInternalError(w)
		return
	}

	user.EmailConfirmToken = token.Hash
	user.EmailConfirmIssuedAt = time.Now().UTC().Unix()

	if err := ar.UserRepo.AssignUserConfirmToken(r.Context(), token.Hash, time.Now().UTC().Unix(), user.ID); err != nil {
		ar.Logger.Error("Failed to assign confirmation token:", err)
		api.WriteInternalError(w)
		return
	}

	ar.Logger.Info("Confirmation email resent", "userID:", user.ID, "email:", user.Email)
	api.WriteMessage(w, 200, "message", "confirmation email resent")
}
