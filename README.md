# gocode
a quick-setup, fast, Go-chi backend example repository

## setup
it is recommended that you replace every `github.com/akramboussanni/gocode` to your package name.

gocode template supports a .env file to load env vars from.

supported env vars:
```
necessary:
JWT_SECRET=[my jwt secret]

SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=example@contoso.com
SMTP_SENDER=example@contoso.com
SMTP_PASSWORD=supersecret
```

## mailing
by default, the mailer (smtp) will use embedded templates in `mailer/templates/*.html`. at runtime, if a templates/ folder is found, with a matching template name, it will replace the embedded template (only on first load, not any time during app lifetime)

## running/building
gocode supports both `sqlite` and `postgres`. to run locally, use `go run -tags debug cmd/server/main.go` which will run sqlite automatically. in prod build, postgres will be used.

## warnings
this is for my personal use/reference, the repo doesnt have caching, other features that may be necessary for a prod server.
