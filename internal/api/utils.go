package api

import (
	"encoding/json"
	"net/http"
)

// WriteJSON writes the given data as a JSON response with the specified status code.
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
