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

func Init() {
	godotenv.Load()
	var err error
	JwtSecret, err = base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		panic(err)
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
}
