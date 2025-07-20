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
