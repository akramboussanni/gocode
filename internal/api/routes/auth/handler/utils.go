package handler

import (
	"time"

	"github.com/akramboussanni/gocode/internal/jwt"
	"github.com/akramboussanni/gocode/internal/mailer"
	"github.com/akramboussanni/gocode/internal/model"
	"github.com/akramboussanni/gocode/internal/utils"
	"github.com/google/uuid"
)

func GenerateTokenAndSendEmail(email, templateName, subject string) (*model.Token, error) {
	token, err := utils.GetRandomToken(16)
	if err != nil {
		return nil, err
	}

	headers := []mailer.MailHeader{
		mailer.MakeHeader("Subject", subject),
		mailer.MakeHeader("To", email),
	}

	err = mailer.Send(templateName, headers, map[string]any{"Token": token.Raw})
	if err != nil {
		return nil, err
	}

	return token, nil
}

func GenerateLogin(user *model.User) LoginResponse {
	now := time.Now().Unix()
	claims := jwt.Claims{
		UserID:   user.ID,
		TokenID:  uuid.New().String(),
		IssuedAt: now,
		Email:    user.Email,
		Role:     user.Role,
	}

	token := jwt.CreateJwt(claims)
	sessionToken := token.WithType(jwt.Credentials).GenerateToken()
	refreshToken := token.WithType(jwt.Refresh).GenerateToken()

	return LoginResponse{Session: sessionToken, Refresh: refreshToken}
}
