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

	db.Init("todo")
	db.RunMigrations("./migrations")

	mailer.Init(config.MailerSetting)

	repos := repo.NewRepos(db.DB)
	r := routes.SetupRouter(repos)

	log.Println("server will run @ localhost:9520")
	http.ListenAndServe(":9520", r)
}
