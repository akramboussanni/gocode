package authhandler

import (
	"github.com/akramboussanni/gocode/internal/jwt"
	"github.com/akramboussanni/gocode/internal/mailer"
	"github.com/akramboussanni/gocode/internal/model"
	"github.com/akramboussanni/gocode/internal/utils"
)

func GenerateTokenAndSendEmail(email, templateName, subject, url string) (*model.Token, error) {
	token, err := utils.GetRandomToken(16)
	if err != nil {
		return nil, err
	}

	headers := []mailer.MailHeader{
		mailer.MakeHeader("Subject", subject),
		mailer.MakeHeader("To", email),
	}

	err = mailer.Send(templateName, headers, map[string]any{"Token": token.Raw, "Url": url})
	if err != nil {
		return nil, err
	}

	return token, nil
}

func GenerateLogin(token jwt.Jwt) LoginResponse {
	sessionToken := token.WithType(jwt.Credentials).GenerateToken()
	refreshToken := token.WithType(jwt.Refresh).GenerateToken()

	return LoginResponse{Session: sessionToken, Refresh: refreshToken}
}
