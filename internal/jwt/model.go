package jwt

import "time"

type Jwt struct {
	Header  Header
	Payload Claims
}

var tokenExpirations = map[TokenType]int64{
	Credentials: 24 * 3600,     //24h
	Refresh:     7 * 24 * 3600, //1week
}

func (j Jwt) WithType(t TokenType) Jwt {
	j.Payload.Type = t
	j.Payload.Expiration = time.Now().UTC().Unix() + tokenExpirations[t]
	return j
}

type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type Claims struct {
	UserID     int64     `json:"sub"`
	TokenID    string    `json:"jti"`
	IssuedAt   int64     `json:"iat"`
	Expiration int64     `json:"exp"`
	Email      string    `json:"email"`
	Role       string    `json:"role"`
	Type       TokenType `json:"type"`
}

type TokenType string

const (
	Credentials TokenType = "credential"
	Refresh     TokenType = "refresh"
)
