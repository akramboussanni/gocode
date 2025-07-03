package config

import (
	"encoding/base64"
	"os"

	"github.com/akramboussanni/gocode/internal/mailer"
	"github.com/joho/godotenv"
)

var JwtSecret []byte
var MailerSetting mailer.MailerSetting

func Init() {
	godotenv.Load()
	var err error
	JwtSecret, err = base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		panic(err)
	}

	MailerSetting = mailer.MailerSetting{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     os.Getenv("SMTP_PORT"),
		Sender:   os.Getenv("SMTP_SENDER"),
		Password: os.Getenv("SMTP_PASSWORD"),
	}
}
