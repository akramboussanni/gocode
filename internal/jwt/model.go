package jwt

type Jwt struct {
	Header  JwtHeader
	Payload Claims
}

type JwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type Claims struct {
	UserID     int64  `json:"sub"`
	TokenID    string `json:"jti"`
	IssuedAt   int64  `json:"iat"`
	Expiration int64  `json:"exp"`
	Email      string `json:"email"`
	Role       string `json:"role"`
}
