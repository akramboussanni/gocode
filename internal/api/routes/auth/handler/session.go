package handler

import (
	"log"
	"math"
	"net/http"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/middleware"
	"github.com/akramboussanni/gocode/internal/model"
	"github.com/akramboussanni/gocode/internal/utils"
)

// @Summary Authenticate user and get JWT tokens
// @Description Authenticate user with email and password, returning session and refresh JWT tokens. User must have confirmed their email address.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param X-Recaptcha-Token header string false "reCAPTCHA verification token (optional if reCAPTCHA is not configured)"
// @Param request body LoginRequest true "User login credentials"
// @Success 200 {object} LoginResponse "Authentication successful - returns session and refresh tokens"
// @Failure 400 {object} api.ErrorResponse "Invalid request format or missing required fields"
// @Failure 401 {object} api.ErrorResponse "Invalid credentials or email not confirmed"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (8 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error"
// @Router /api/auth/login [post]
func (ar *AuthRouter) HandleLogin(w http.ResponseWriter, r *http.Request) {
	cred, err := api.DecodeJSON[LoginRequest](w, r)
	if err != nil {
		return
	}

	user, err := ar.UserRepo.GetUserByEmail(r.Context(), cred.Email)
	if err != nil || user == nil {
		log.Println(err)
		api.WriteInvalidCredentials(w)
		return
	}

	if !utils.ComparePassword(user.PasswordHash, cred.Password) || !user.EmailConfirmed {
		api.WriteInvalidCredentials(w)
		return
	}

	api.WriteJSON(w, 200, GenerateLogin(user))
}

// @Summary Refresh JWT tokens
// @Description Refresh user's JWT tokens using a valid refresh token. The old refresh token will be revoked and new session/refresh tokens will be issued.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param X-Recaptcha-Token header string false "reCAPTCHA verification token (optional if reCAPTCHA is not configured)"
// @Param request body TokenRequest true "Refresh token"
// @Success 200 {object} LoginResponse "Token refresh successful - returns new session and refresh tokens"
// @Failure 400 {object} api.ErrorResponse "Invalid request format or missing token"
// @Failure 401 {object} api.ErrorResponse "Invalid, expired, or revoked refresh token"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (8 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error"
// @Router /api/auth/refresh [post]
func (ar *AuthRouter) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	req, err := api.DecodeJSON[TokenRequest](w, r)
	if err != nil {
		return
	}

	claims := middleware.GetClaims(w, r, req.Token, config.JwtSecret, ar.TokenRepo)
	if claims == nil {
		return
	}

	user, err := ar.UserRepo.GetUserById(r.Context(), claims.UserID)
	if err != nil || user == nil {
		log.Println(err)
		api.WriteInvalidCredentials(w)
		return
	}

	blacklist := model.JwtBlacklist{
		TokenID:   claims.TokenID,
		UserID:    claims.UserID,
		ExpiresAt: math.MaxInt64,
	}

	ar.TokenRepo.RevokeToken(r.Context(), blacklist)
	api.WriteJSON(w, 200, GenerateLogin(user))
}
