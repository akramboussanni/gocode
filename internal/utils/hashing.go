package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/akramboussanni/gocode/config"
	"golang.org/x/crypto/bcrypt"
)

func HashJwt(message string) string {
	h := hmac.New(sha256.New, config.JwtSecret)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func ComparePassword(hashed, plain string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	return err == nil
}

func GenerateRandomBytes(bytes uint8) ([]byte, error) {
	b := make([]byte, bytes)

	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

type Token struct {
	Raw  string
	Hash string
}

func GetRandomToken(bytes uint8) (*Token, error) {
	b, err := GenerateRandomBytes(bytes)
	if err != nil {
		return nil, err
	}

	enc := base64.URLEncoding.EncodeToString(b)
	hashed := sha256.Sum256(b)

	return &Token{
		Raw:  enc,
		Hash: base64.URLEncoding.EncodeToString(hashed[:]),
	}, err
}
