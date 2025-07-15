// this file contains translations
package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/akramboussanni/gocode/internal/api"
	"github.com/akramboussanni/gocode/internal/mailer"
	"github.com/akramboussanni/gocode/internal/utils"
)

func (ar *AuthRouter) HandleConfirmEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	b, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	sha := sha256.Sum256(b)
	hash := base64.URLEncoding.EncodeToString(sha[:])
	user, err := ar.UserRepo.GetUserByConfirmationToken(r.Context(), hash)
	if err != nil {
		http.Error(w, "invalid credentials (no acc found)", http.StatusUnauthorized)
		return
	}

	if user.EmailConfirmed { // this scenario should not happen. normally
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	expiry := user.EmailConfirmIssuedAt + 3600*24 //24h expiry
	if expiry < time.Now().UTC().Unix() {
		http.Error(w, "expired token, please request a new one.", http.StatusUnauthorized)
		return
	}

	if err = ar.UserRepo.MarkUserConfirmed(r.Context(), user.ID); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (ar *AuthRouter) HandleResendConfirmation(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Email string `json:"email"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	user, err := ar.UserRepo.GetUserByEmail(r.Context(), req.Email)
	if err != nil || user == nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if user.EmailConfirmed {
		http.Error(w, "email already confirmed", http.StatusBadRequest)
		return
	}

	confirmToken, err := utils.GetRandomToken(16)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	user.EmailConfirmToken = confirmToken.Hash
	user.EmailConfirmIssuedAt = time.Now().UTC().Unix()

	if err := ar.UserRepo.UpdateUser(r.Context(), user); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	headers := []mailer.MailHeader{
		mailer.MakeHeader("Subject", "Email confirmation"),
		mailer.MakeHeader("To", user.Email),
	}

	if err := mailer.Send("confirmregister", headers, map[string]any{"Token": confirmToken.Raw}); err != nil {
		http.Error(w, "failed to send email", http.StatusInternalServerError)
		return
	}

	api.WriteJSON(w, 200, map[string]string{"message": "confirmation email resent"})
}
