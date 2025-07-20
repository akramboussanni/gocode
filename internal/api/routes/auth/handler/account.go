package handler

import (
	"net/http"
	"time"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/ctxutil"
	"github.com/akramboussanni/gocode/internal/jwt"
	"github.com/akramboussanni/gocode/internal/middleware"
	"github.com/akramboussanni/gocode/internal/model"
)

// @Summary Get user profile
// @Description Get current user's profile information
// @Tags Account
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} model.User "User profile information"
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "Server error"
// @Router /api/auth/me [get]
func (ar *AuthRouter) HandleProfile(w http.ResponseWriter, r *http.Request) {
	user := ctxutil.FetchUserWithContext(r.Context(), w, ar.UserRepo.GetUserByIdSafe)
	if user == nil {
		return
	}

	api.WriteJSON(w, 200, user)
}

// @Summary Logout user
// @Description Logout user by revoking their JWT token
// @Tags Account
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {string} string "Logout successful"
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "Server error"
// @Router /api/auth/logout [post]
func (ar *AuthRouter) HandleLogout(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaimsFromHeader(w, r, config.JwtSecret, ar.TokenRepo)
	if claims == nil || claims.Type != jwt.Credentials {
		return
	}

	expiration := time.Unix(claims.Expiration, 0)

	err := ar.TokenRepo.RevokeToken(r.Context(), model.JwtBlacklist{
		TokenID:   claims.TokenID,
		UserID:    claims.UserID,
		ExpiresAt: expiration.UTC().Unix(),
	})

	if err != nil {
		api.WriteInternalError(w)
		return
	}

	w.WriteHeader(http.StatusOK)
}
