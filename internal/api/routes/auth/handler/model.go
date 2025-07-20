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

type TokenRequest struct {
	Token string `json:"token"`
}

type EmailRequest struct {
	Email string `json:"email"`
}

type PasswordResetRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type PasswordChangeRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}
