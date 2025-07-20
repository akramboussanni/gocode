# gocode
a quick-setup, fast, Go-chi backend example repository

## developing
when testing in dev mode, it is heavily recommended to apply debug tan (done by adding `-tags=debug` in your command, e.g. `go run -tags=debug cmd/server/main.go`). the benefits of doing so are:
- sqlite instead of postgres
- runs a swagger server @ `localhost:9520/swagger/`


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

optional:
RECAPTCHA_V3_SECRET=obtain from google website
RECAPTCHA_V3_ENABLED=true|false
```

## mailing
by default, the mailer (smtp) will use embedded templates in `mailer/templates/*.html`. at runtime, if a templates/ folder is found, with a matching template name, it will replace the embedded template (only on first load, not any time during app lifetime)

## running/building

## warnings
this is for my personal use/reference, the repo doesnt have caching, other features that may be necessary for a prod server.
