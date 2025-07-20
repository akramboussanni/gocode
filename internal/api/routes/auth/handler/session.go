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

// @Summary User login
// @Description Authenticate user and return JWT tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body Credentials true "Login credentials"
// @Success 200 {object} LoginResponse "Login successful with tokens"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Invalid credentials or email not confirmed"
// @Failure 500 {string} string "Server error"
// @Router /api/auth/login [post]
func (ar *AuthRouter) HandleLogin(w http.ResponseWriter, r *http.Request) {
	cred, err := api.DecodeJSON[Credentials](w, r)
	if err != nil {
		return
	}

	user, err := ar.UserRepo.GetUserByEmail(r.Context(), cred.Email)
	if err != nil || user == nil {
		log.Println(err)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if !utils.ComparePassword(user.PasswordHash, cred.Password) || !user.EmailConfirmed {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	api.WriteJSON(w, 200, GenerateLogin(user))
}

// @Summary Refresh JWT token
// @Description Refresh user's JWT token using refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body TokenRequest true "Refresh token"
// @Success 200 {object} LoginResponse "New tokens generated"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Invalid credentials"
// @Failure 500 {string} string "Server error"
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
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
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
