// @title gocode API
// @version 1.0.0
// @description A secure, fast, and feature-rich Go-Chi backend with JWT authentication, email verification, and password management. Built with modern Go practices and comprehensive security features.
// @termsOfService https://github.com/akramboussanni/gocode/blob/main/LICENSE

// @contact.name API Support
// @contact.url https://github.com/akramboussanni/gocode/issues
// @contact.email support@example.com

// @license.name MIT License
// @license.url https://github.com/akramboussanni/gocode/blob/main/LICENSE

// @host localhost:9520
// @BasePath /
// @schemes http https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT Bearer token for authenticated endpoints. Format: "Bearer <token>". Required for endpoints marked with @Security BearerAuth.

// @securityDefinitions.apikey RecaptchaToken
// @in header
// @name X-Recaptcha-Token
// @description reCAPTCHA verification token for bot protection. Optional - only required if reCAPTCHA is configured in environment variables. Obtain from reCAPTCHA widget.

// @tag.name Authentication
// @tag.description User registration, login, and token management endpoints. reCAPTCHA verification is optional if configured.

// @tag.name Account
// @tag.description User profile and account management endpoints. All endpoints require JWT authentication.

// @tag.name Email Verification
// @tag.description Email confirmation and verification endpoints. reCAPTCHA verification is optional if configured.

// @tag.name Password Management
// @tag.description Password reset, change, and recovery endpoints. Public endpoints have optional reCAPTCHA, authenticated endpoints require JWT.

package main

import (
	"log"
	"net/http"

	"github.com/akramboussanni/gocode/config"
	"github.com/akramboussanni/gocode/internal/api/routes"
	"github.com/akramboussanni/gocode/internal/db"
	"github.com/akramboussanni/gocode/internal/mailer"
	"github.com/akramboussanni/gocode/internal/repo"
	"github.com/akramboussanni/gocode/internal/utils"
)

func main() {
	config.Init()
	err := utils.InitSnowflake(1)
	if err != nil {
		panic(err)
	}

	db.Init(config.DbConnectionString)
	db.RunMigrations("./migrations")

	mailer.Init(config.MailerSetting)

	repos := repo.NewRepos(db.DB)
	r := routes.SetupRouter(repos)

	log.Println("server will run @ localhost:9520")
	http.ListenAndServe(":9520", r)
}
