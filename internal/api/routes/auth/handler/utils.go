package handler

import (
	"github.com/akramboussanni/gocode/internal/mailer"
	"github.com/akramboussanni/gocode/internal/utils"
)

func GenerateTokenAndSendEmail(email, templateName, subject string) (rawToken string, hashToken string, err error) {
	token, err := utils.GetRandomToken(16)
	if err != nil {
		return "", "", err
	}

	headers := []mailer.MailHeader{
		mailer.MakeHeader("Subject", subject),
		mailer.MakeHeader("To", email),
	}

	err = mailer.Send(templateName, headers, map[string]any{"Token": token.Raw})
	if err != nil {
		return "", "", err
	}

	return token.Raw, token.Hash, nil
}
