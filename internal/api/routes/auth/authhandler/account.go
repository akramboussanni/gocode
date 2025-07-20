package authhandler

import (
	"math"
	"net/http"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/jwt"
	"github.com/akramboussanni/gocode/internal/middleware"
	"github.com/akramboussanni/gocode/internal/model"
	"github.com/akramboussanni/gocode/internal/utils"
)

// @Summary Get current user profile
// @Description Retrieve the current authenticated user's profile information. Returns safe user data (excluding sensitive fields like password hash).
// @Tags Account
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param Authorization header string true "Bearer JWT token" default(Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)
// @Success 200 {object} model.User "User profile information (safe fields only)"
// @Failure 401 {object} api.ErrorResponse "Unauthorized - invalid or missing JWT token"
// @Failure 429 {object} api.ErrorResponse "Rate limit exceeded (30 requests per minute)"
// @Failure 500 {object} api.ErrorResponse "Internal server error"
// @Router /api/auth/me [get]
func (ar *AuthRouter) HandleProfile(w http.ResponseWriter, r *http.Request) {
	user := utils.FetchUserWithContext(r.Context(), w, ar.UserRepo.GetUserByIdSafe)
	if user == nil {
		return
	}

	api.WriteJSON(w, 200, user)
}

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
	claims := middleware.GetClaimsFromHeader(w, r, config.JwtSecret, ar.TokenRepo)
	if claims == nil || claims.Type != jwt.Credentials {
		return
	}

	err := ar.TokenRepo.RevokeToken(r.Context(), model.JwtBlacklist{
		TokenID:   claims.TokenID,
		UserID:    claims.UserID,
		ExpiresAt: math.MaxInt64,
	})

	if err != nil {
		api.WriteInternalError(w)
		return
	}

	w.WriteHeader(http.StatusOK)
}
