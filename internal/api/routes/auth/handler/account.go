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

func (ar *AuthRouter) HandleProfile(w http.ResponseWriter, r *http.Request) {
	user := ctxutil.FetchUserWithContext(r.Context(), w, ar.UserRepo.GetUserByIdSafe)
	if user == nil {
		return
	}

	api.WriteJSON(w, 200, user)
}

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
