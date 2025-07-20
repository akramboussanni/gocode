package handler

type Credentials struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Session string `json:"session"`
	Refresh string `json:"refresh"`
}
