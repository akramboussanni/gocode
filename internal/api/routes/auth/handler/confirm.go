// this file contains translations
package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/akramboussanni/gocode/internal/api"
)

func (ar *AuthRouter) HandleConfirmEmail(w http.ResponseWriter, r *http.Request) {
	req, err := api.DecodeJSON[TokenRequest](w, r)
	if err != nil {
		return
	}

	b, err := base64.URLEncoding.DecodeString(req.Token)
	if err != nil {
		api.WriteInternalError(w)
		return
	}

	sha := sha256.Sum256(b)
	hash := base64.URLEncoding.EncodeToString(sha[:])
	user, err := ar.UserRepo.GetUserByConfirmationToken(r.Context(), hash)
	if err != nil {
		api.WriteInvalidCredentials(w)
		return
	}

	if user.EmailConfirmed { // this scenario should not happen. normally
		api.WriteInvalidCredentials(w)
		return
	}

	expiry := user.EmailConfirmIssuedAt + 3600*24 //24h expiry
	if expiry < time.Now().UTC().Unix() {
		http.Error(w, "expired token, please request a new one", http.StatusUnauthorized)
		return
	}

	if err = ar.UserRepo.MarkUserConfirmed(r.Context(), user.ID); err != nil {
		api.WriteInternalError(w)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (ar *AuthRouter) HandleResendConfirmation(w http.ResponseWriter, r *http.Request) {
	req, err := api.DecodeJSON[EmailRequest](w, r)
	if err != nil {
		return
	}

	user, err := ar.UserRepo.GetUserByEmail(r.Context(), req.Email)
	if err != nil || user == nil {
		api.WriteInvalidCredentials(w)
		return
	}

	if user.EmailConfirmed {
		http.Error(w, "email already confirmed", http.StatusBadRequest)
		return
	}

	token, err := GenerateTokenAndSendEmail(user.Email, "confirmregister", "Email confirmation")
	if err != nil {
		api.WriteInternalError(w)
		return
	}

	user.EmailConfirmToken = token.Hash
	user.EmailConfirmIssuedAt = time.Now().UTC().Unix()

	if err := ar.UserRepo.AssignUserConfirmToken(r.Context(), token.Hash, time.Now().UTC().Unix(), user.ID); err != nil {
		api.WriteInternalError(w)
		return
	}

	api.WriteMessage(w, 200, "message", "confirmation email resent")
}
