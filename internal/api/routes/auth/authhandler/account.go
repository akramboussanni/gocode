package authhandler

import (
	"net/http"

	"github.com/akramboussanni/gocode/internal/api"
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
	ar.Logger.Info("HandleProfile called")
	user, ok := utils.UserFromContext(r.Context())
	if !ok {
		ar.Logger.Error("Failed to get user from context")
		api.WriteInternalError(w)
		return
	}

	utils.StripUnsafeFields(user)
	ar.Logger.Info("Profile retrieved", "userID:", user.ID)
	api.WriteJSON(w, 200, user)
}
