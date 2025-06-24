package config

import (
	"encoding/base64"
	"os"

	"github.com/joho/godotenv"
)

var JwtSecret []byte

func Init() {
	godotenv.Load()
	var err error
	JwtSecret, err = base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET"))
	if err != nil {
		panic(err)
	}
}
