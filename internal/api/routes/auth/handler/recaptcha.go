package handler

import (
	"encoding/json"
	"net/http"
)

var RecaptchaSecret string

func Init(secret string) {
	RecaptchaSecret = secret
}

func (ar *AuthRouter) HandleValidate(w http.ResponseWriter, r *http.Request) {
	var payload RecaptchaRequestPayload

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Response == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if payload.Response == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
}
