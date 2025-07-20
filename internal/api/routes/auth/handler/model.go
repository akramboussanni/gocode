package handler

// @Description User registration and login credentials
type Credentials struct {
	Username string `json:"username" example:"johndoe" binding:"required"`
	Email    string `json:"email" example:"john@example.com" binding:"required"`
	Password string `json:"password" example:"securepassword123" binding:"required"`
}

// @Description Login response with JWT tokens
type LoginResponse struct {
	Session string `json:"session" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	Refresh string `json:"refresh" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// @Description Token request for various operations
type TokenRequest struct {
	Token string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." binding:"required"`
}

// @Description Email request for various operations
type EmailRequest struct {
	Email string `json:"email" example:"john@example.com" binding:"required"`
}

// @Description Password reset request with token and new password
type PasswordResetRequest struct {
	Token       string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." binding:"required"`
	NewPassword string `json:"new_password" example:"newsecurepassword123" binding:"required"`
}

// @Description Password change request with old and new password
type PasswordChangeRequest struct {
	OldPassword string `json:"old_password" example:"oldpassword123" binding:"required"`
	NewPassword string `json:"new_password" example:"newsecurepassword123" binding:"required"`
}
