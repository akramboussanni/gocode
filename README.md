# gocode
a quick-setup, fast, Go-chi backend example repository

## setup
it is recommended that you replace every `github.com/akramboussanni/gocode` to your package name.

gocode template supports a .env file to load env vars from.

supported env vars:
```
necessary:
JWT_SECRET=[my jwt secret]
```

## running/building
gocode supports both `sqlite/postgres`. to run locally, use `go run -tags debug cmd/server/main.go` which will run sqlite automatically.

## warnings
this is for my personal use/reference, the repo doesnt have caching, ratelimits, other features that may be necessary for a prod server.