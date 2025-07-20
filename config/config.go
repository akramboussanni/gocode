package config

import (
	"encoding/base64"
	"os"
	"strconv"

	"github.com/akramboussanni/gocode/internal/mailer"
	"github.com/joho/godotenv"
)

var JwtSecret []byte
var MailerSetting mailer.MailerSetting
var RecaptchaSecret string

func Init() {
	godotenv.Load()
	var err error
	JwtSecret, err = base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		panic(err)
	}

	if len(JwtSecret) < 32 {
		panic("jwt secret must be at least 32bytes")
	}

	mPort, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil {
		panic(err)
	}

	MailerSetting = mailer.MailerSetting{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     mPort,
		Username: os.Getenv("SMTP_USERNAME"),
		Sender:   os.Getenv("SMTP_SENDER"),
		Password: os.Getenv("SMTP_PASSWORD"),
	}

	recaptchaEnabled, err := strconv.ParseBool(os.Getenv("RECAPTCHA_V3_ENABLED"))
	if err == nil && recaptchaEnabled {
		RecaptchaSecret = os.Getenv("RECAPTCHA_V3_SECRET")
	}

	if recaptchaEnabled {
	}
}
