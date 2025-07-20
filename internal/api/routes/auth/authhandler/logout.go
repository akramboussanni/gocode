package authhandler

import (
	"math"
	"net/http"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/jwt"
	"github.com/akramboussanni/gocode/internal/middleware"
	"github.com/akramboussanni/gocode/internal/model"
)

// @Summary Logout user and revoke session
// @Description Logout the current user by revoking their JWT session token. The token will be added to the blacklist and cannot be used again.
// @Tags Account
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer JWT token" default(Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)
// @Success 200 {string} string "Logout successful - session token revoked"
// @Failure 401 {object} api.ErrorResponse "Unauthorized - invalid or missing JWT token"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (8 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error during token revocation"
// @Router /api/auth/logout [post]
func (ar *AuthRouter) HandleLogout(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaimsFromHeader(w, r, config.JwtSecret, ar.UserRepo, ar.TokenRepo)
	if claims == nil || claims.Type != jwt.Credentials {
		return
	}

	err := ar.TokenRepo.RevokeToken(r.Context(), model.JwtBlacklist{
		TokenID:   claims.TokenID,
		UserID:    claims.UserID,
		ExpiresAt: math.MaxInt64,
	})

	if err != nil {
		ar.Logger.Error("Failed to revoke token during logout:", err)
		api.WriteInternalError(w)
		return
	}

	ar.Logger.Info("User logged out successfully", "userID:", claims.UserID, "tokenID:", claims.TokenID)
	w.WriteHeader(http.StatusOK)
}

// @Summary Logout user from all devices
// @Description Logout the current user from all devices by invalidating all active JWT sessions. This revokes all tokens by incrementing the user's session ID, making all previously issued tokens invalid.
// @Tags Account
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer JWT token" default(Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)
// @Success 200 {string} string "Logout from all devices successful - all sessions revoked"
// @Failure 401 {object} api.ErrorResponse "Unauthorized - invalid or missing JWT token"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (8 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error during session revocation"
// @Router /api/auth/logout-all [post]
func (ar *AuthRouter) HandleLogoutEverywhere(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaimsFromHeader(w, r, config.JwtSecret, ar.UserRepo, ar.TokenRepo)
	if claims == nil || claims.Type != jwt.Credentials {
		return
	}

	err := ar.UserRepo.IncrementJwtSessionID(r.Context(), claims.UserID)

	if err != nil {
		ar.Logger.Error("Failed to revoke all sessions during logout everywhere:", err)
		api.WriteInternalError(w)
		return
	}

	ar.Logger.Info("User logged out from all devices", "userID:", claims.UserID)
	w.WriteHeader(http.StatusOK)
}
