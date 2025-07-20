package utils

import (
	"context"
	"net/http"

	"github.com/akramboussanni/gocode/internal/model"
)

type contextKey string

const UserIDKey contextKey = "userID"

func UserIDFromContext(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(UserIDKey).(int64)
	return id, ok
}

type userFetcher func(ctx context.Context, id int64) (*model.User, error)

func FetchUserWithContext(ctx context.Context, w http.ResponseWriter, fetch userFetcher) *model.User {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return nil
	}

	user, err := fetch(ctx, userID)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return nil
	}

	return user
}
