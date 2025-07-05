package mailer

import (
	"embed"
	"html/template"
	"os"
)

var tmplCache = map[string]*template.Template{}

//go:embed templates/*
var embedded embed.FS

func GetTemplate(name string) (*template.Template, error) {
	if tmpl, ok := tmplCache[name]; ok {
		return tmpl, nil
	}

	path := "templates/" + name + ".html"
	tmpl, err := loadTemplate(path)

	if err != nil {
		return nil, err
	}

	tmplCache[name] = tmpl
	return tmpl, nil
}

func loadTemplate(path string) (*template.Template, error) {
	if _, err := os.Stat(path); err == nil {
		return template.ParseFiles(path)
	}
	return template.ParseFS(embedded, path)
}
