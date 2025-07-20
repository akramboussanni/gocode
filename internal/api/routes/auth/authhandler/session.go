package authhandler

import (
	"math"
	"net/http"
	"time"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/jwt"
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
	ip := utils.GetClientIP(r)
	ar.Logger.Info("HandleLogin called", "remoteAddr:", ip)
	cred, err := api.DecodeJSON[LoginRequest](w, r)
	if err != nil {
		ar.Logger.Error("Failed to decode login request:", err)
		return
	}

	user, err := ar.UserRepo.GetUserByEmail(r.Context(), cred.Email)
	if err != nil || user == nil {
		ar.Logger.Warn("Login failed: user not found or db error", "email:", cred.Email, "err:", err)
		api.WriteInvalidCredentials(w)
		return
	}

	lockedOut, err := ar.LockoutRepo.IsLockedOut(r.Context(), user.ID, ip)
	if err != nil {
		ar.Logger.Error("Error checking lockout:", err)
		api.WriteInternalError(w)
		return
	}

	if lockedOut {
		ar.Logger.Warn("Account locked out", "userID:", user.ID, "ip:", ip)
		api.WriteMessage(w, 423, "error", "account locked")
		return
	}

	if !utils.ComparePassword(user.PasswordHash, cred.Password) {
		now := time.Now().UTC().Unix()
		nowMicro := time.Now().UTC().UnixMicro()
		err := ar.LockoutRepo.AddFailedLogin(r.Context(), model.FailedLogin{ID: nowMicro, UserID: user.ID, IPAddress: ip, AttemptedAt: now, Active: true})

		if err != nil {
			ar.Logger.Error("Failed to add failed login:", err)
			api.WriteInternalError(w)
			return
		}

		count, err := ar.LockoutRepo.CountRecentFailures(r.Context(), user.ID, ip)
		if err != nil {
			ar.Logger.Error("Failed to count recent failures:", err)
			api.WriteInternalError(w)
			return
		}

		if count > config.LockoutCount {
			err := ar.LockoutRepo.AddLockout(r.Context(), model.Lockout{
				ID:          nowMicro,
				UserID:      user.ID,
				IPAddress:   ip,
				LockedUntil: now + config.LockoutDuration,
				Reason:      "failed logins",
				Active:      true,
			})

			if err != nil {
				ar.Logger.Error("Failed to add lockout:", err)
				api.WriteInternalError(w)
				return
			}

			ar.Logger.Warn("User locked out due to failed logins", "userID:", user.ID, "ip:", ip)
			api.WriteMessage(w, 423, "error", "account locked")
			return
		}

		ar.Logger.Warn("Invalid password for user", "userID:", user.ID)
		api.WriteInvalidCredentials(w)
		return
	}

	if !user.EmailConfirmed {
		ar.Logger.Warn("Login attempt with unconfirmed email", "userID:", user.ID)
		api.WriteInvalidCredentials(w)
		return
	}

	ar.Logger.Info("User login successful", "userID:", user.ID)
	api.WriteJSON(w, 200, GenerateLogin(jwt.CreateJwtFromUser(user)))
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
	ar.Logger.Info("HandleRefresh called")
	req, err := api.DecodeJSON[TokenRequest](w, r)
	if err != nil {
		ar.Logger.Error("Failed to decode refresh request:", err)
		return
	}

	claims := middleware.GetClaims(w, r, req.Token, config.JwtSecret, ar.TokenRepo)
	if claims == nil || claims.Type != jwt.Refresh {
		ar.Logger.Warn("Invalid or missing refresh token")
		return
	}

	user, err := ar.UserRepo.GetUserByID(r.Context(), claims.UserID)
	if err != nil || user == nil {
		ar.Logger.Warn("Refresh failed: user not found or db error", "userID:", claims.UserID, "err:", err)
		api.WriteInvalidCredentials(w)
		return
	}

	blacklist := model.JwtBlacklist{
		TokenID:   claims.TokenID,
		UserID:    claims.UserID,
		ExpiresAt: math.MaxInt64,
	}

	err = ar.TokenRepo.RevokeToken(r.Context(), blacklist)
	if err != nil {
		ar.Logger.Error("Failed to revoke old refresh token:", err)
	}
	ar.Logger.Info("Refresh token successful", "userID:", user.ID)
	api.WriteJSON(w, 200, GenerateLogin(jwt.CreateJwtFromUser(user)))
}
