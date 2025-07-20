# gocode
a quick-setup, fast, Go-chi backend example repository

## todo
account lockout

## developing
when testing in dev mode, it is heavily recommended to apply debug tan (done by adding `-tags=debug` in your command, e.g. `go run -tags=debug cmd/server/main.go`). the benefits of doing so are:
- sqlite instead of postgres
- runs a swagger server @ `localhost:9520/swagger/`

### swagger
to update swagger docs, run `swag init -g cmd/server/main.go`

## setup
it is recommended that you replace every `github.com/akramboussanni/gocode` to your package name.

gocode template supports a .env file to load env vars from.

supported env vars:
```
required:
JWT_SECRET=[my jwt secret] - at least 32 chars

SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=example@contoso.com
SMTP_SENDER=example@contoso.com
SMTP_PASSWORD=supersecret

optional:
RECAPTCHA_V3_ENABLED=true|false
RECAPTCHA_V3_SECRET=obtain from google website
```

## deploying
### build the repo
you can build the repo with postgres (highly recommended) using `go build cmd/server/main.go`. this will produce a `main` executable file (`main.exe` on windows) that you can put on the server

### add migrations
your db will not be migrated. you need to transfer the `migrations` folder onto your server in the working dir of the `main` executable file

### setup env vars
you can use `.env` file or normal env vars for the server. the available env vars are available above.

## mailing
by default, the mailer (smtp) will use embedded templates in `mailer/templates/*.html`. at runtime, if a templates/ folder is found, with a matching template name, it will replace the embedded template (only on first load, not any time during app lifetime)

## warnings
this is for my personal use/reference, the repo doesnt have caching, other features that may be necessary for a prod server.
