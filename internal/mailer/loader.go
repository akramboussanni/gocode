package mailer

import (
	"html/template"
)

var tmplCache = map[string]*template.Template{}

func loadTemplate(name string) (*template.Template, error) {
	if tmpl, ok := tmplCache[name]; ok {
		return tmpl, nil
	}

}
